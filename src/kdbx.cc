/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "kdbx.hh"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <sstream>
#ifdef DEBUG
#include <iostream>
#endif

#include <openssl/sha.h>

#include "base64.hh"
#include "cipher.hh"
#include "icon.hh"
#include "key.hh"
#include "metadata.hh"
#include "pugixml.hh"
#include "random.hh"
#include "security.hh"
#include "stream.hh"
#include "util.hh"

namespace keepass {

constexpr uint32_t kKdbxSignature0 = 0x9aa2d903;
constexpr uint32_t kKdbxSignature1 = 0xb54bfb67;
constexpr uint32_t kKdbxVersionCriticalMask = 0xffff0000;
constexpr uint32_t kKdbxVersionCriticalMin = 0x00030001;

constexpr std::array<uint8_t, 16> kKdbxCipherAes = { {
  0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50,
  0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff 
} };

constexpr std::array<uint8_t, 8> kKdbxInnerRandomStreamInitVec = {
  0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a
};

enum class kKdbxCompressionFlags : uint32_t {
  kNone,
  kGzip,

  kCount
};

enum class kKdbxRandomStream : uint32_t {
  kNone,
  kArcFourVariant,
  kSalsa20,

  kCount
};

#pragma pack(push, 1)
struct KdbxHeader {
  uint32_t signature0;
  uint32_t signature1;
  uint32_t version;
};
static_assert(sizeof(KdbxHeader) == 12,
              "bad packing of header structure.");

struct KdbxHeaderField {
  enum Id : uint8_t {
    kEndOfHeader = 0,
    //kComment = 1,
    kCipherId = 2,
    kCompressionFlags = 3,
    kMasterSeed = 4,
    kTransformSeed = 5,
    kTransformRounds = 6,
    kExcryptionInitVec = 7,
    kInnerRandomStreamKey = 8,
    kContentStreamStartBytes = 9,
    kInnerRandomStreamId = 10
  } id;

  uint16_t size;
};
static_assert(sizeof(KdbxHeaderField) == 3,
              "bad packing of bitfield header structure.");
#pragma pack(pop)

void KdbxFile::Reset() {
  binary_pool_.clear();
  icon_pool_.clear();
  group_pool_.clear();
  header_hash_ = { 0 };
}

std::shared_ptr<Group> KdbxFile::GetGroup(const std::string& uuid) {
  if (uuid.empty())
    return nullptr;

  auto it = group_pool_.find(uuid);
  if (it != group_pool_.end())
    return it->second;

  std::shared_ptr<Group> group = std::make_shared<Group>();
  group_pool_.insert(std::make_pair(uuid, group));
  return group;
}

std::time_t KdbxFile::ParseDateTime(const char* text) const {
  // Check for the special KeePass 1x "never" timestamp.
  if (std::string(text) == "2999-12-28T22:59:59Z")
    return 0;
  
  std::tm tm;
  char* res = strptime(text, "%Y-%m-%dT%H:%M:%S", &tm);
  if (res == nullptr)
     throw std::runtime_error("malformed xml, unable to parse date.");

  // Format is expected to always be in UTC.
  assert(*res == 'Z' || *res == '\0');

  return timegm(&tm);
}

protect<std::string> KdbxFile::ParseProtectedString(
    const pugi::xml_node& node,
    const char* name,
    RandomObfuscator& obfuscator) const {
  pugi::xml_node val_node = node.child(name);
  if (val_node) {
    bool prot = val_node.attribute("Protected").as_bool();
    if (prot) {
      std::string val = base64_decode(val_node.text().as_string());
      if (!val.empty())
        return protect<std::string>(obfuscator.Process(val), true);
    }

    return protect<std::string>(
        val_node.text().as_string(),
        prot || val_node.attribute("ProtectedInMemory").as_bool());
  }

  return protect<std::string>(std::string(), false);
}

std::shared_ptr<Metadata> KdbxFile::ParseMeta(const pugi::xml_node& meta_node,
                                              RandomObfuscator& obfuscator) {
  std::shared_ptr<Metadata> meta = std::make_shared<Metadata>();

  // Parse header hash and store in member for checking later.
  std::string hash_str = base64_decode(meta_node.child_value("HeaderHash"));
  if (hash_str.size() != 32)
    throw std::runtime_error("invalid header hash.");
  std::copy(hash_str.begin(), hash_str.end(), header_hash_.begin());

  meta->set_generator(meta_node.child_value("Generator"));
  meta->set_database_name(temporal<std::string>(
      meta_node.child_value("DatabaseName"),
      ParseDateTime(meta_node.child_value("DatabaseNameChanged"))));
  meta->set_database_desc(temporal<std::string>(
      meta_node.child_value("DatabaseDescription"),
      ParseDateTime(meta_node.child_value("DatabaseDescriptionChanged"))));
  meta->set_default_username(temporal<std::string>(
      meta_node.child_value("DefaultUserName"),
      ParseDateTime(meta_node.child_value("DefaultUserNameChanged"))));
  meta->set_maintenance_hist_days(
      meta_node.child("MaintenanceHistoryDays").text().as_uint(365));
  meta->set_database_color(meta_node.child_value("Color"));
  meta->set_master_key_changed(ParseDateTime(
      meta_node.child_value("MasterKeyChanged")));
  meta->set_master_key_change_rec(
      meta_node.child("MasterKeyChangeRec").text().as_llong(-1));
  meta->set_master_key_change_force(
      meta_node.child("MasterKeyChangeForce").text().as_llong(-1));

  pugi::xml_node mp_node = meta_node.child("MemoryProtection");
  meta->memory_protection().set_title(
      mp_node.child("ProtectTitle").text().as_bool());
  meta->memory_protection().set_username(
      mp_node.child("ProtectUserName").text().as_bool());
  meta->memory_protection().set_password(
      mp_node.child("ProtectPassword").text().as_bool(true));
  meta->memory_protection().set_url(
      mp_node.child("ProtectURL").text().as_bool());
  meta->memory_protection().set_notes(
      mp_node.child("ProtectNotes").text().as_bool());

  if (meta_node.child("RecycleBinEnabled").text().as_bool(true))
    meta->set_recycle_bin(GetGroup(meta_node.child_value("RecycleBinUUID")));
  else
    meta->set_recycle_bin(std::shared_ptr<Group>());
  meta->set_recycle_bin_changed(ParseDateTime(
      meta_node.child_value("RecycleBinChanged")));

  meta->set_entry_templates(GetGroup(
      meta_node.child_value("EntryTemplatesGroup")));
  meta->set_entry_templates_changed(ParseDateTime(
      meta_node.child_value("EntryTemplatesGroupChanged")));

  meta->set_history_max_items(
      meta_node.child("HistoryMaxItems").text().as_int(-1));
  meta->set_history_max_size(
      meta_node.child("HistoryMaxSize").text().as_llong(-1));

  // Note that we're not parsing "LastSelectedGroup" and "LastTopVisibleGroup"
  // here. They will be parsed later by ParseXml(). The reason is that we need
  // to parse all groups first.

  pugi::xml_node icons_node = meta_node.child("CustomIcons");
  if (icons_node) {
    for (pugi::xml_node icon_node = icons_node.child("Icon"); icon_node;
        icon_node = icon_node.next_sibling("Icon")) {
      std::string data = base64_decode(icon_node.child_value("Data"));
      if (data.empty())
        continue;

      std::shared_ptr<Icon> icon = std::make_shared<Icon>(data);
      meta->AddIcon(icon);

      icon_pool_.insert(std::make_pair(icon_node.child_value("UUID"), icon));
    }
  }

  pugi::xml_node bins_node = meta_node.child("Binaries");
  if (bins_node) {
    for (pugi::xml_node bin_node = bins_node.child("Binary"); bin_node;
        bin_node = bin_node.next_sibling("Binary")) {
      std::string id = bin_node.attribute("ID").value();

      protect<std::string> data;

      if (bin_node.attribute("Protected").as_bool()) {
        data = protect<std::string>(obfuscator.Process(
            base64_decode(bin_node.text().as_string())), true);
      } else {
        if (bin_node.attribute("Compressed").as_bool()) {
          std::stringstream raw_stream(
              base64_decode(bin_node.text().as_string()));
          gzip_istreambuf gzip_streambuf(raw_stream);
          std::istream gzip_stream(&gzip_streambuf);

          data = protect<std::string>(
              consume<std::string>(gzip_stream),
              bin_node.attribute("ProtectedInMemory").as_bool());
        } else {
          data = protect<std::string>(
              base64_decode(bin_node.text().as_string()),
              bin_node.attribute("ProtectedInMemory").as_bool());
        }
      }

      std::shared_ptr<Binary> binary = std::make_shared<Binary>(data);
      meta->AddBinary(binary);

      binary_pool_.insert(std::make_pair(id, binary));
    }
  }

  pugi::xml_node data_node = meta_node.child("CustomData");
  if (data_node) {
    for (pugi::xml_node item_node = data_node.child("Item"); item_node;
        item_node = item_node.next_sibling("Item")) {
      std::string key = item_node.child_value("Key");
      std::string value = item_node.child_value("Value");
      if (key.empty()) {
        assert(false);
        continue;
      }

      meta->AddField(key, value);
    }
  }

  return meta;
}

std::shared_ptr<Entry> KdbxFile::ParseEntry(
    const pugi::xml_node& entry_node,
    std::array<uint8_t, 16>& entry_uuid,
    RandomObfuscator& obfuscator) {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();

  std::string uuid_str = base64_decode(entry_node.child_value("UUID"));
  if (uuid_str.size() != 16)
    throw std::runtime_error("invalid entry uuid.");
  std::copy(uuid_str.begin(), uuid_str.end(), entry_uuid.begin());

  entry->set_uuid(entry_uuid);
  entry->set_icon(entry_node.child("IconID").text().as_uint());
  entry->set_fg_color(entry_node.child_value("ForegroundColor"));
  entry->set_bg_color(entry_node.child_value("BackgroundColor"));
  entry->set_override_url(entry_node.child_value("OverrideURL"));
  entry->set_tags(entry_node.child_value("Tags"));

  if (entry_node.child("CustomIconUUID")) {
    auto it = icon_pool_.find(entry_node.child_value("CustomIconUUID"));
    if (it != icon_pool_.end()) {
      entry->set_custom_icon(it->second);
    } else {
      assert(false);
    }
  }
 
  pugi::xml_node times_node = entry_node.child("Times");
  if (times_node) {
    entry->set_creation_time(ParseDateTime(
        times_node.child_value("CreationTime")));
    entry->set_modification_time(ParseDateTime(
        times_node.child_value("LastModificationTime")));
    entry->set_access_time(ParseDateTime(
        times_node.child_value("LastAccessTime")));
    entry->set_expiry_time(ParseDateTime(
        times_node.child_value("ExpiryTime")));
    entry->set_move_time(ParseDateTime(
        times_node.child_value("LocationChanged")));
    entry->set_expires(
        times_node.child("Expires").text().as_bool());
    entry->set_usage_count(
        times_node.child("UsageCount").text().as_uint());
  }

  // Auto type.
  pugi::xml_node autotype_node = entry_node.child("AutoType");
  if (autotype_node) {
    entry->auto_type().set_enabled(
        autotype_node.child("Enabled").text().as_bool());
    entry->auto_type().set_obfuscation(
        autotype_node.child("DataTransferObfuscation").text().as_uint());
    entry->auto_type().set_sequence(
        autotype_node.child_value("DefaultSequence"));

    for (pugi::xml_node ass_node = autotype_node.child("Association"); ass_node;
        ass_node = ass_node.next_sibling("Association")) {
      entry->auto_type().AddAssociation(
          ass_node.child_value("Window"),
          ass_node.child_value("KeystrokeSequence"));
    }
  }

  // Read string fields.
  for (pugi::xml_node str_node = entry_node.child("String"); str_node;
      str_node = str_node.next_sibling("String")) {
    std::string key = str_node.child_value("Key");
    protect<std::string> val = ParseProtectedString(
        str_node, "Value", obfuscator);

    if (key == "Title") {
      entry->set_title(val);
    } else if (key == "URL") {
      entry->set_url(val);
    } else if (key == "UserName") {
      entry->set_username(val);
    } else if (key == "Password") {
      entry->set_password(val);
    } else if (key == "Notes") {
      entry->set_notes(val);
    } else {
      entry->AddCustomField(key, val);
    }
  }

  // Read binary fields.
  for (pugi::xml_node bin_node = entry_node.child("Binary"); bin_node;
      bin_node = bin_node.next_sibling("Binary")) {
    std::string key = bin_node.child_value("Key");
    std::shared_ptr<Binary> binary;

    pugi::xml_node val_node = bin_node.child("Value");
    if (val_node) {
      pugi::xml_attribute ref_attr = val_node.attribute("Ref");
      if (ref_attr) {
        auto it = binary_pool_.find(ref_attr.value());
        if (it == binary_pool_.end()) {
          throw std::runtime_error(
              "entry refers to non-existing binary data.");
        }

        binary = it->second;
      } else {
        protect<std::string> prot_val;

        if (bin_node.attribute("Protected").as_bool()) {
          prot_val = protect<std::string>(obfuscator.Process(
              base64_decode(bin_node.text().as_string())), true);
        } else {
          if (bin_node.attribute("Compressed").as_bool()) {
            std::stringstream raw_stream(
                base64_decode(bin_node.text().as_string()));
            gzip_istreambuf gzip_streambuf(raw_stream);
            std::istream gzip_stream(&gzip_streambuf);

            prot_val = protect<std::string>(
                consume<std::string>(gzip_stream),
                bin_node.attribute("ProtectedInMemory").as_bool());
          } else {
            prot_val = protect<std::string>(
                base64_decode(bin_node.text().as_string()),
                bin_node.attribute("ProtectedInMemory").as_bool());
          }
        }

        binary = std::make_shared<Binary>(prot_val);
      }
    }

    std::shared_ptr<Entry::Attachment> attachment =
        std::make_shared<Entry::Attachment>();
    attachment->set_name(key);
    attachment->set_binary(binary);

    entry->AddAttachment(attachment);
  }

  // Read history entries.
  pugi::xml_node history_node = entry_node.child("History");
  if (history_node) {
    for (pugi::xml_node subentry_node = history_node.child("Entry"); subentry_node;
        subentry_node = subentry_node.next_sibling("Entry")) {
      std::array<uint8_t, 16> subentry_uuid = { 0 };
      entry->AddHistoryEntry(ParseEntry(subentry_node,
                                        subentry_uuid,
                                        obfuscator));
    }
  }

  return entry;
}

std::shared_ptr<Group> KdbxFile::ParseGroup(
    const pugi::xml_node& group_node,
    RandomObfuscator& obfuscator) {
  std::shared_ptr<Group> group = std::make_shared<Group>();
  group_pool_.insert(std::make_pair(group_node.child_value("UUID"), group));

  std::string uuid_str = base64_decode(group_node.child_value("UUID"));
  if (uuid_str.size() != 16)
    throw std::runtime_error("invalid group uuid.");

  std::array<uint8_t, 16> uuid = { 0 };
  std::copy(uuid_str.begin(), uuid_str.end(), uuid.begin());

  group->set_uuid(uuid);
  group->set_name(group_node.child_value("Name"));
  group->set_notes(group_node.child_value("Notes"));
  group->set_icon(group_node.child("IconID").text().as_uint());

  if (group_node.child("CustomIconUUID")) {
    auto icon = icon_pool_.find(group_node.child_value("CustomIconUUID"));
    if (icon != icon_pool_.end()) {
      group->set_custom_icon(icon->second);
    } else {
      assert(false);
    }
  }

  pugi::xml_node times_node = group_node.child("Times");
  if (times_node) {
    group->set_creation_time(ParseDateTime(
        times_node.child_value("CreationTime")));
    group->set_modification_time(ParseDateTime(
        times_node.child_value("LastModificationTime")));
    group->set_access_time(ParseDateTime(
        times_node.child_value("LastAccessTime")));
    group->set_expiry_time(ParseDateTime(
        times_node.child_value("ExpiryTime")));
    group->set_move_time(ParseDateTime(
        times_node.child_value("LocationChanged")));
    group->set_expires(
        times_node.child("Expires").text().as_bool());
    group->set_usage_count(
        times_node.child("UsageCount").text().as_uint());
  }

  group->set_expanded(group_node.child("IsExpanded").text().as_bool());
  group->set_default_autotype_sequence(
      group_node.child_value("DefaultAutoTypeSequence"));
  group->set_autotype(group_node.child("EnableAutoType").text().as_bool());
  group->set_search(group_node.child("EnableSearching").text().as_bool());

  uuid_str = base64_decode(group_node.child_value("LastTopVisibleEntry"));
  if (uuid_str.size() != 16)
    throw std::runtime_error("invalid uuid in group field.");

  std::fill(uuid.begin(), uuid.end(), 0);
  std::copy(uuid_str.begin(), uuid_str.end(), uuid.begin());

  for (pugi::xml_node entry_node = group_node.child("Entry"); entry_node;
      entry_node = entry_node.next_sibling("Entry")) {
    std::array<uint8_t, 16> entry_uuid = { 0 };
    std::shared_ptr<Entry> entry = ParseEntry(entry_node, entry_uuid, obfuscator);
    group->AddEntry(entry);

    if (entry_uuid == uuid) {
      assert(group->last_visible_entry().expired());
      group->set_last_visible_entry(entry);
    }
  }

  for (pugi::xml_node subgroup_node = group_node.child("Group"); subgroup_node;
      subgroup_node = subgroup_node.next_sibling("Group")) {
    group->AddGroup(ParseGroup(subgroup_node, obfuscator));
  }

  return group;
}

void KdbxFile::ParseXml(std::istream& src,
                        RandomObfuscator& obfuscator,
                        Database& db) {
  pugi::xml_document doc;
  if (!doc.load(src, pugi::parse_default | pugi::parse_trim_pcdata))
    throw std::runtime_error("unable to parse xml.");

  pugi::xml_node kpf_node = doc.child("KeePassFile");
  if (!kpf_node)
    throw std::runtime_error("malformed xml.");

  pugi::xml_node meta_node = kpf_node.child("Meta");
  if (!meta_node)
    throw std::runtime_error("malformed xml.");

  pugi::xml_node group_node = kpf_node.child("Root").child("Group");
  if (!group_node)
    throw std::runtime_error("malformed xml.");

  std::shared_ptr<Metadata> meta = ParseMeta(meta_node, obfuscator);
  std::shared_ptr<Group> root = ParseGroup(group_node, obfuscator);

  db.set_meta(meta);
  db.set_root(root);

  // When first parsing the meta data we haven't yet parsed all groups so we
  // have to wait until every group is parsed before parsing the final parts of
  // the meta data.
  auto it = group_pool_.find(meta_node.child_value("LastSelectedGroup"));
  if (it != group_pool_.end()) {
    meta->set_last_selected_group(it->second);
  } else {
    assert(false);
  }

  it = group_pool_.find(meta_node.child_value("LastTopVisibleGroup"));
  if (it != group_pool_.end()) {
    meta->set_last_visible_group(it->second);
  } else {
    assert(false);
  }
}

#ifdef DEBUG
void KdbxFile::PrintXml(pugi::xml_document& doc) {
  static const char* kNodeTypeNames[] = {
    "null", "document", "element", "pcdata", "cdata", "comment", "pi",
    "declaration"
  };

  struct XmlTreeWalker : pugi::xml_tree_walker {
   public:
    virtual bool for_each(pugi::xml_node& node) override {
      for (int i = 0; i < depth(); ++i)
        std::cout << "  ";

      std::cout << kNodeTypeNames[node.type()] << ": name=\"" << node.name() <<
          "\"; value=\"" << node.value() << "\"" << std::endl;
      return true;
    }
  };

  XmlTreeWalker walker;
  doc.traverse(walker);
}
#endif

std::unique_ptr<Database> KdbxFile::Import(const std::string& path,
                                           const Key& key) {
  Reset();

  std::ifstream src(path, std::ios::binary);
  if (!src.is_open())
    throw std::runtime_error("file not found.");

  // Read header.
  KdbxHeader header;
  src.read(reinterpret_cast<char *>(&header), sizeof(header));
  if (!src.good())
    throw std::runtime_error("unable to read file header.");

  if (header.signature0 != kKdbxSignature0 ||
      header.signature1 != kKdbxSignature1) {
    throw std::runtime_error("not a keepass2 database.");
  }

  uint32_t kdb_ver =
      header.version & kKdbxVersionCriticalMask;
  uint32_t req_ver =
      kKdbxVersionCriticalMin & kKdbxVersionCriticalMask;

  if (kdb_ver > req_ver)
    throw std::runtime_error("unsupported database version, database is too new.");

  std::array<uint8_t, 32> inner_random_stream_key = { { 0 } };
  std::array<uint8_t, 32> content_start_bytes = { { 0 } };

  std::unique_ptr<Database> db(new Database());

  // Read header fields.
  bool done = false;
  while (!done && src.good()) {
    KdbxHeaderField header_field = consume<KdbxHeaderField>(src);

    // Read the header field into a separate buffer before parsing. This is to
    // guard against reading outside the field as well as for making sure to
    // read the complete field regardless of how much of it that we parse.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field),
                    header_field.size,
                    [&src]() { return src.get(); });
    if (!src.good())
      throw std::runtime_error("unable to read group field.");

    assert(field.str().size() == header_field.size);

    switch (header_field.id) {
      case KdbxHeaderField::kEndOfHeader:
        done = true;
        break;
      case KdbxHeaderField::kCipherId:
        if (consume<std::array<uint8_t, 16>>(field) != kKdbxCipherAes)
          throw std::runtime_error("unsupported crypto algorithm in header.");
        db->set_cipher(Database::Cipher::kAes);
        break;
      case KdbxHeaderField::kCompressionFlags: {
        uint32_t comp_flags = consume<uint32_t>(field);
        if (comp_flags > static_cast<uint32_t>(kKdbxCompressionFlags::kCount))
          throw std::runtime_error("unsupported compression method in header.");
        db->set_compressed(comp_flags ==
            static_cast<uint32_t>(kKdbxCompressionFlags::kGzip));
        break;
      }
      case KdbxHeaderField::kMasterSeed:
        db->set_master_seed(consume<std::vector<uint8_t>>(field));
        break;
      case KdbxHeaderField::kTransformSeed:
        if (header_field.size != 32)
          throw std::runtime_error("illegal transform seed size in header.");
        db->set_transform_seed(consume<std::array<uint8_t, 32>>(field));
        break;
      case KdbxHeaderField::kTransformRounds:
        db->set_transform_rounds(consume<uint64_t>(field));
        break;
      case KdbxHeaderField::kExcryptionInitVec:
        if (header_field.size != 16) {
          throw std::runtime_error(
              "illegal initialization vector size in header.");
        }
        db->set_init_vector(consume<std::array<uint8_t, 16>>(field));
        break;
      case KdbxHeaderField::kInnerRandomStreamKey:
        if (header_field.size != 32) {
          throw std::runtime_error(
              "illegal protected stream key size in header.");
        }
        inner_random_stream_key = consume<std::array<uint8_t, 32>>(field);
        break;
      case KdbxHeaderField::kContentStreamStartBytes:
        if (header_field.size != 32) {
          throw std::runtime_error(
              "illegal protected stream start sequence in header.");
        }
        content_start_bytes = consume<std::array<uint8_t, 32>>(field);
        break;
      case KdbxHeaderField::kInnerRandomStreamId: {
        // FIXME: Investigate if support for other random streams is necessary.
        uint32_t inner_random_stream_id = consume<uint32_t>(field);
        if (inner_random_stream_id !=
            static_cast<uint32_t>(kKdbxRandomStream::kSalsa20)) {
          throw std::runtime_error("unsupported random stream in header.");
        }
        /*if (inner_random_stream_id >
            static_cast<uint32_t>(kKdbxRandomStream::kCount)) {
          throw std::runtime_error("unsupported random stream in header.");
        }*/
        break;
      }
      default:
        throw std::runtime_error("illegal field in group.");
        break;
    }
  }

  // Compute the header hash.
  std::streampos header_end = src.tellg();
  src.seekg(0, std::ios::beg);
  std::vector<char> header_data;
  header_data.resize(header_end);
  src.read(header_data.data(), header_end);

  std::array<uint8_t, 32> header_hash;
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, header_data.data(), header_data.size());
  SHA256_Final(header_hash.data(), &sha256);

  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> transformed_key = key.Transform(
      db->transform_seed(), db->transform_rounds(),
      Key::SubKeyResolution::kHashSubKeys);
  std::array<uint8_t, 32> final_key;

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, db->master_seed().data(), db->master_seed().size());
  SHA256_Update(&sha256, transformed_key.data(), transformed_key.size());
  SHA256_Final(final_key.data(), &sha256);

  std::unique_ptr<Cipher<16>> cipher;
  switch (db->cipher()) {
    case Database::Cipher::kAes:
      cipher.reset(new AesCipher(final_key, db->init_vector()));
      break;
    case Database::Cipher::kTwofish:
      cipher.reset(new TwofishCipher(final_key, db->init_vector()));
      break;
    default:
      assert(false);
      break;
  }

  // Decrypt the content.
  std::stringstream content;

  try {
    decrypt_cbc(src, content, *cipher);
  } catch (std::runtime_error& e) {
    throw std::runtime_error("invalid password.");
  }

  std::array<uint8_t, 32> content_start_bytes_tst;
  content.read(reinterpret_cast<char*>(content_start_bytes_tst.data()),
               content_start_bytes_tst.size());
  if (!content.good() || content_start_bytes != content_start_bytes_tst)
    throw std::runtime_error("invalid password or database is corrupt.");

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256,
                inner_random_stream_key.data(),
                inner_random_stream_key.size());
  SHA256_Final(final_inner_random_stream_key.data(), &sha256);
  RandomObfuscator obfuscator(final_inner_random_stream_key,
                              kKdbxInnerRandomStreamInitVec);

  // Parse XML content.
  hashed_istreambuf hashed_streambuf(content);
  std::istream hashed_stream(&hashed_streambuf);

  if (db->compressed()) {
    gzip_istreambuf gzip_streambuf(hashed_stream);
    std::istream gzip_stream(&gzip_streambuf);

    ParseXml(gzip_stream, obfuscator, *db.get());
  } else {
    ParseXml(hashed_stream, obfuscator, *db.get());
  }

  // Validate header hash.
  if (header_hash_ != header_hash)
    throw std::runtime_error("header checksum error.");

  return db;
}

void KdbxFile::Export(const std::string&, const Database&,
                      const Key&) {
  Reset();
}

}   // namespace keepass
