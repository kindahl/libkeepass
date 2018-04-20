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
#include "exception.hh"
#include "format.hh"
#include "icon.hh"
#include "io.hh"
#include "iterator.hh"
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
  } id = kEndOfHeader;

  uint16_t size = 0;

  KdbxHeaderField() = default;
  KdbxHeaderField(Id new_id, uint16_t new_size) :
      id(new_id), size(new_size) {}
  KdbxHeaderField(KdbxHeaderField&& other) {
    id = std::move(other.id);
    size = std::move(other.size);
  }
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

std::shared_ptr<Group> KdbxFile::GetGroup(const std::string& uuid_str) {
  if (uuid_str.empty())
    return nullptr;

  auto it = group_pool_.find(uuid_str);
  if (it != group_pool_.end())
    return it->second;

  std::array<uint8_t, 16> uuid;
  base64_decode(uuid_str, bounds_checked(uuid));

  std::shared_ptr<Group> group = std::make_shared<Group>();
  group->set_uuid(uuid);

  group_pool_.insert(std::make_pair(uuid_str, group));
  return group;
}

std::time_t KdbxFile::ParseDateTime(const char* text) const {
  // Check for the special KeePass 1x "never" timestamp.
  if (std::string(text) == "2999-12-28T22:59:59Z")
    return 0;
  
  std::tm tm;
  char* res = strptime(text, "%Y-%m-%dT%H:%M:%S", &tm);
  if (res == nullptr) {
    assert(false);
    return 0;
  }

  // Format is expected to always be in UTC.
  assert(*res == 'Z' || *res == '\0');

  return timegm(&tm);
}

std::string KdbxFile::WriteDateTime(std::time_t time) const {
  if (time == 0)
    return "2999-12-28T22:59:59Z";

  char buffer[128];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ",
                std::gmtime(&time));
  return buffer;
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

void KdbxFile::WriteProtectedString(pugi::xml_node& node,
                                    const protect<std::string>& str,
                                    RandomObfuscator& obfuscator) const {
  if (str.is_protected()) {
    node.append_attribute("Protected").set_value("True");
    node.text().set(base64_encode(obfuscator.Process(*str)).c_str());
  } else {
    node.text().set(str->c_str());
  }
}

std::shared_ptr<Metadata> KdbxFile::ParseMeta(const pugi::xml_node& meta_node,
                                              RandomObfuscator& obfuscator) {
  std::shared_ptr<Metadata> meta = std::make_shared<Metadata>();

  // Parse header hash and store in member for checking later.
  base64_decode(meta_node.child_value("HeaderHash"),
                bounds_checked(header_hash_));

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
      std::vector<uint8_t> data;
      base64_decode(icon_node.child_value("Data"), std::back_inserter(data));
      if (data.empty())
        continue;

      std::array<uint8_t, 16> uuid;
      base64_decode(icon_node.child_value("UUID"), bounds_checked(uuid));

      std::shared_ptr<Icon> icon = std::make_shared<Icon>(uuid, data);
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

      bool compressed = false;
      if (bin_node.attribute("Protected").as_bool()) {
        data = protect<std::string>(obfuscator.Process(
            base64_decode(bin_node.text().as_string())), true);
      } else {
        if (bin_node.attribute("Compressed").as_bool()) {
          compressed = true;
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
      binary->set_compress(compressed);
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

void KdbxFile::WriteMeta(pugi::xml_node& meta_node,
                         RandomObfuscator& obfuscator,
                         std::shared_ptr<Metadata> meta) {
  meta_node.append_child("HeaderHash").text().set(base64_encode(
      header_hash_.begin(), header_hash_.end()).c_str());
  meta_node.append_child("Generator").text().set(meta->generator().c_str());
  meta_node.append_child("DatabaseName").text().set(
      meta->database_name()->c_str());
  meta_node.append_child("DatabaseNameChanged").text().set(WriteDateTime(
      meta->database_name().time()).c_str());
  meta_node.append_child("DatabaseDescription").text().set(
      meta->database_desc()->c_str());
  meta_node.append_child("DatabaseDescriptionChanged").text().set(
      WriteDateTime(meta->database_desc().time()).c_str());
  meta_node.append_child("DefaultUserName").text().set(
      meta->default_username()->c_str());
  meta_node.append_child("DefaultUserNameChanged").text().set(WriteDateTime(
      meta->default_username().time()).c_str());
  meta_node.append_child("MaintenanceHistoryDays").text().set(
      meta->maintenance_hist_days());
  meta_node.append_child("Color").text().set(meta->database_color().c_str());
  meta_node.append_child("MasterKeyChanged").text().set(WriteDateTime(
      meta->master_key_changed()).c_str());
  meta_node.append_child("MasterKeyChangeRec").text().set(
      static_cast<long long>(meta->master_key_change_rec()));
  meta_node.append_child("MasterKeyChangeForce").text().set(
      static_cast<long long>(meta->master_key_change_force()));

  pugi::xml_node mp_node = meta_node.append_child("MemoryProtection");
  mp_node.append_child("ProtectTitle").text().set(
      meta->memory_protection().title());
  mp_node.append_child("ProtectUserName").text().set(
      meta->memory_protection().username());
  mp_node.append_child("ProtectPassword").text().set(
      meta->memory_protection().password());
  mp_node.append_child("ProtectURL").text().set(
      meta->memory_protection().url());
  mp_node.append_child("ProtectNotes").text().set(
      meta->memory_protection().notes());

  if (meta->recycle_bin()) {
    meta_node.append_child("RecycleBinEnabled").text().set(true);
    meta_node.append_child("RecycleBinUUID").text().set(base64_encode(
        meta->recycle_bin()->uuid().begin(),
        meta->recycle_bin()->uuid().end()).c_str());
  } else {
    meta_node.append_child("RecycleBinEnabled").text().set(false);
  }
  meta_node.append_child("RecycleBinChanged").text().set(WriteDateTime(
      meta->recycle_bin_changed()).c_str());

  if (meta->entry_templates()) {
    meta_node.append_child("EntryTemplatesGroup").text().set(base64_encode(
        meta->entry_templates()->uuid().begin(),
        meta->entry_templates()->uuid().end()).c_str());
  } else {
    assert(false);
  }
  meta_node.append_child("EntryTemplatesGroupChanged").text().set(
      WriteDateTime(meta->entry_templates_changed()).c_str());

  meta_node.append_child("HistoryMaxItems").text().set(
      meta->history_max_items());
  meta_node.append_child("HistoryMaxSize").text().set(
      static_cast<long long>(meta->history_max_size()));

  if (auto group = meta->last_selected_group().lock()) {
    meta_node.append_child("LastSelectedGroup").text().set(base64_encode(
        group->uuid().begin(), group->uuid().end()).c_str());
  }

  if (auto group = meta->last_visible_group().lock()) {
    meta_node.append_child("LastTopVisibleGroup").text().set(base64_encode(
        group->uuid().begin(), group->uuid().end()).c_str());
  }

  pugi::xml_node icons_node = meta_node.append_child("CustomIcons");
  for (auto icon : meta->icons()) {
    pugi::xml_node icon_node = icons_node.append_child("Icon");
    icon_node.append_child("UUID").text().set(base64_encode(
        icon->uuid().begin(), icon->uuid().end()).c_str());
    icon_node.append_child("Data").text().set(base64_encode(
        icon->data().begin(), icon->data().end()).c_str());
  }

  uint32_t binary_id = 0;
  pugi::xml_node bins_node = meta_node.append_child("Binaries");
  for (auto binary : meta->binaries()) {
    pugi::xml_node bin_node = bins_node.append_child("Binary");
    bin_node.append_attribute("ID").set_value(binary_id);

    if (binary->data().is_protected()) {
      bin_node.append_attribute("Protected").set_value("True");
      bin_node.text().set(base64_encode(obfuscator.Process(
          *binary->data())).c_str());
    } else {
      if (binary->compress()) {
        bin_node.append_attribute("Compressed").set_value("True");
        std::stringstream compressed_data;

        gzip_ostreambuf gzip_streambuf(compressed_data);
        std::ostream gzip_stream(&gzip_streambuf);
        std::copy(binary->data()->begin(), binary->data()->end(),
                  std::ostreambuf_iterator<char>(gzip_stream));
        gzip_stream.flush();

        bin_node.text().set(base64_encode(
              std::istreambuf_iterator<char>(compressed_data), 
              std::istreambuf_iterator<char>()).c_str());
      } else {
        bin_node.text().set(base64_encode(*binary->data()).c_str());
      }
    }

    binary_pool_.insert(std::make_pair(std::to_string(binary_id), binary));

    ++binary_id;
  }

  pugi::xml_node data_node = meta_node.append_child("CustomData");
  for (auto field : meta->fields()) {
    pugi::xml_node item_node = data_node.append_child("Item");
    item_node.append_child("Key").text().set(field.key().c_str());
    item_node.append_child("Value").text().set(field.value().c_str());
  }
}

std::shared_ptr<Entry> KdbxFile::ParseEntry(
    const pugi::xml_node& entry_node,
    std::array<uint8_t, 16>& entry_uuid,
    RandomObfuscator& obfuscator) {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();

  base64_decode(entry_node.child_value("UUID"), bounds_checked(entry_uuid));

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
          throw FormatError(
              "Entry attachment refers to non-existing binary data.");
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

void KdbxFile::WriteEntry(pugi::xml_node& entry_node,
                          RandomObfuscator& obfuscator,
                          std::shared_ptr<Entry> entry) {
  entry_node.append_child("UUID").text().set(base64_encode(
      entry->uuid().begin(), entry->uuid().end()).c_str());
  entry_node.append_child("IconID").text().set(entry->icon());
  entry_node.append_child("ForegroundColor").text().set(
      entry->fg_color().c_str());
  entry_node.append_child("BackgroundColor").text().set(
      entry->bg_color().c_str());
  entry_node.append_child("OverrideURL").text().set(
      entry->override_url().c_str());
  entry_node.append_child("Tags").text().set(entry->tags().c_str());

  if (auto icon = entry->custom_icon().lock()) {
    entry_node.append_child("CustomIconUUID").text().set(
        base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
  }

  pugi::xml_node times_node = entry_node.append_child("Times");
  times_node.append_child("CreationTime").text().set(WriteDateTime(
      entry->creation_time()).c_str());
  times_node.append_child("LastModificationTime").text().set(WriteDateTime(
      entry->modification_time()).c_str());
  times_node.append_child("LastAccessTime").text().set(WriteDateTime(
      entry->access_time()).c_str());
  times_node.append_child("ExpiryTime").text().set(WriteDateTime(
      entry->expiry_time()).c_str());
  times_node.append_child("LocationChanged").text().set(WriteDateTime(
      entry->move_time()).c_str());
  times_node.append_child("Expires").text().set(entry->expires());
  times_node.append_child("UsageCount").text().set(entry->usage_count());

  pugi::xml_node autotype_node = entry_node.append_child("AutoType");
  autotype_node.append_child("Enabled").text().set(entry->auto_type().enabled());
  autotype_node.append_child("DataTransferObfuscation").text().set(
      entry->auto_type().obfuscation());
  autotype_node.append_child("DefaultSequence").text().set(
      entry->auto_type().sequence().c_str());

  for (auto ass : entry->auto_type().associations()) {
    pugi::xml_node ass_node = autotype_node.append_child("Association");
    ass_node.append_child("Window").text().set(ass.window().c_str());
    ass_node.append_child("KeystrokeSequence").text().set(
        ass.sequence().c_str());
  }

  // Write string fields.
  pugi::xml_node str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("Title");
  pugi::xml_node val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->title(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("URL");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->url(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("UserName");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->username(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("Password");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->password(), obfuscator);

  str_node = entry_node.append_child("String");
  str_node.append_child("Key").text().set("Notes");
  val_node = str_node.append_child("Value");
  WriteProtectedString(val_node, entry->notes(), obfuscator);

  for (auto field : entry->custom_fields()) {
    str_node = entry_node.append_child("String");
    str_node.append_child("Key").text().set(field.key().c_str());
    val_node = str_node.append_child("Value");
    WriteProtectedString(val_node, field.value(), obfuscator);
  }

  // Write binary fields.
  for (auto attachment : entry->attachments()) {
    pugi::xml_node bin_node = entry_node.append_child("Binary");
    bin_node.append_child("Key").text().set(attachment->name().c_str());

    bool found_in_pool = false;
    for (auto it : binary_pool_) {
      if (it.second == attachment->binary()) {
        bin_node.append_child("Value").append_attribute("Ref").set_value(
            it.first.c_str());
        found_in_pool = true;
        break;
      }
    }

    if (!found_in_pool) {
      bin_node.append_child("Value").text().set(base64_encode(
          attachment->binary()->data()).c_str());
    }
  }

  // Write history entries.
  pugi::xml_node history_node = entry_node.append_child("History");
  for (auto histentry : entry->history()) {
    pugi::xml_node histentry_node = history_node.append_child("Entry");
    WriteEntry(histentry_node, obfuscator, histentry);
  }
}

std::shared_ptr<Group> KdbxFile::ParseGroup(
    const pugi::xml_node& group_node,
    RandomObfuscator& obfuscator) {
  std::shared_ptr<Group> group = std::make_shared<Group>();
  group_pool_.insert(std::make_pair(group_node.child_value("UUID"), group));

  std::array<uint8_t, 16> uuid = { 0 };
  base64_decode(group_node.child_value("UUID"), bounds_checked(uuid));

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

  base64_decode(group_node.child_value("LastTopVisibleEntry"),
                bounds_checked(uuid));

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

void KdbxFile::WriteGroup(pugi::xml_node& group_node,
                          RandomObfuscator& obfuscator,
                          std::shared_ptr<Group> group) {
  group_node.append_child("UUID").text().set(base64_encode(
      group->uuid().begin(), group->uuid().end()).c_str());
  group_node.append_child("Name").text().set(group->name().c_str());
  group_node.append_child("Notes").text().set(group->notes().c_str());
  group_node.append_child("IconID").text().set(group->icon());

  if (auto icon = group->custom_icon().lock()) {
    group_node.append_child("CustomIconUUID").text().set(
        base64_encode(icon->uuid().begin(), icon->uuid().end()).c_str());
  }

  pugi::xml_node times_node = group_node.append_child("Times");
  times_node.append_child("CreationTime").text().set(WriteDateTime(
      group->creation_time()).c_str());
  times_node.append_child("LastModificationTime").text().set(WriteDateTime(
      group->modification_time()).c_str());
  times_node.append_child("LastAccessTime").text().set(WriteDateTime(
      group->access_time()).c_str());
  times_node.append_child("ExpiryTime").text().set(WriteDateTime(
      group->expiry_time()).c_str());
  times_node.append_child("LocationChanged").text().set(WriteDateTime(
      group->move_time()).c_str());
  times_node.append_child("Expires").text().set(group->expires());
  times_node.append_child("UsageCount").text().set(group->usage_count());

  group_node.append_child("IsExpanded").text().set(group->expanded());
  group_node.append_child("DefaultAutoTypeSequence").text().set(
      group->default_autotype_sequence().c_str());
  group_node.append_child("EnableAutoType").text().set(group->autotype());
  group_node.append_child("EnableSearching").text().set(group->search());

  if (auto entry = group->last_visible_entry().lock()) {
    group_node.append_child("LastTopVisibleEntry").text().set(
        base64_encode(entry->uuid().begin(), entry->uuid().end()).c_str());
  }

  for (auto entry : group->Entries()) {
    pugi::xml_node entry_node = group_node.append_child("Entry");
    WriteEntry(entry_node, obfuscator, entry);
  }

  for (auto subgroup : group->Groups()) {
    pugi::xml_node subgroup_node = group_node.append_child("Group");
    WriteGroup(subgroup_node, obfuscator, subgroup);
  }
}

void KdbxFile::ParseXml(std::istream& src,
                        RandomObfuscator& obfuscator,
                        Database& db) {
  pugi::xml_document doc;
  if (!doc.load(src, pugi::parse_default | pugi::parse_trim_pcdata))
    throw FormatError("Malformed XML in KDBX.");

  pugi::xml_node kpf_node = doc.child("KeePassFile");
  if (!kpf_node)
    throw FormatError("No \"KeePassFile\" element in KDBX XML.");

  pugi::xml_node meta_node = kpf_node.child("Meta");
  if (!meta_node)
    throw FormatError("No \"Meta\" element in KDBX XML.");

  pugi::xml_node group_node = kpf_node.child("Root").child("Group");
  if (!group_node)
    throw FormatError("No \"Root\" or \"Group\" element in KDBX XML.");

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

void KdbxFile::WriteXml(std::ostream& dst, RandomObfuscator& obfuscator,
                        const Database& db) {
  pugi::xml_document doc;

  pugi::xml_node kpf_node = doc.append_child("KeePassFile");
  pugi::xml_node meta_node = kpf_node.append_child("Meta");
  pugi::xml_node group_node =
      kpf_node.append_child("Root").append_child("Group");

  WriteMeta(meta_node, obfuscator, db.meta());
  WriteGroup(group_node, obfuscator, db.root());

  doc.save(dst);
}

std::unique_ptr<Database> KdbxFile::Import(const std::string& path,
                                           const Key& key) {
  Reset();

  std::ifstream src(path, std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  // Read header.
  KdbxHeader header;
  try {
    header = consume<KdbxHeader>(src);
  } catch (std::exception& e) {
    throw FormatError("Not a KDBX database.");
  }
  if (header.signature0 != kKdbxSignature0 ||
      header.signature1 != kKdbxSignature1) {
    throw FormatError("Not a KDBX database.");
  }

  uint32_t kdb_ver =
      header.version & kKdbxVersionCriticalMask;
  uint32_t req_ver =
      kKdbxVersionCriticalMin & kKdbxVersionCriticalMask;
  if (kdb_ver > req_ver) {
    throw FormatError(
        Format() << "KDBX version " << header.version << " is not supported.");
  }

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
      throw IoError("Read error.");

    assert(field.str().size() == header_field.size);

    switch (header_field.id) {
      case KdbxHeaderField::kEndOfHeader:
        done = true;
        break;
      case KdbxHeaderField::kCipherId:
        if (consume<std::array<uint8_t, 16>>(field) != kKdbxCipherAes)
          throw FormatError("Unknown cipher in KDBX.");
        db->set_cipher(Database::Cipher::kAes);
        break;
      case KdbxHeaderField::kCompressionFlags: {
        uint32_t comp_flags = consume<uint32_t>(field);
        if (comp_flags > static_cast<uint32_t>(kKdbxCompressionFlags::kCount))
          throw FormatError("Unknown compression method in KDBX.");
        db->set_compress(comp_flags ==
            static_cast<uint32_t>(kKdbxCompressionFlags::kGzip));
        break;
      }
      case KdbxHeaderField::kMasterSeed:
        db->set_master_seed(consume<std::vector<uint8_t>>(field));
        break;
      case KdbxHeaderField::kTransformSeed:
        if (header_field.size != 32)
          throw FormatError("Illegal transform seed size in KDBX.");
        db->set_transform_seed(consume<std::array<uint8_t, 32>>(field));
        break;
      case KdbxHeaderField::kTransformRounds:
        db->set_transform_rounds(consume<uint64_t>(field));
        break;
      case KdbxHeaderField::kExcryptionInitVec:
        if (header_field.size != 16)
          throw FormatError("Illegal initialization vector size in KDBX.");
        db->set_init_vector(consume<std::array<uint8_t, 16>>(field));
        break;
      case KdbxHeaderField::kInnerRandomStreamKey:
        if (header_field.size != 32)
          throw FormatError("Illegal protected stream key size in KDBX.");
        db->set_inner_random_stream_key(
            consume<std::array<uint8_t, 32>>(field));
        break;
      case KdbxHeaderField::kContentStreamStartBytes:
        if (header_field.size != 32)
          throw FormatError("Illegal stream start sequence size in KDBX.");
        content_start_bytes = consume<std::array<uint8_t, 32>>(field);
        break;
      case KdbxHeaderField::kInnerRandomStreamId: {
        uint32_t inner_random_stream_id = consume<uint32_t>(field);
        if (inner_random_stream_id !=
            static_cast<uint32_t>(kKdbxRandomStream::kSalsa20)) {
          throw FormatError("Unknown random stream in KDBX.");
        }
        break;
      }
      default:
        throw FormatError("Illegal header field in KDBX.");
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
  } catch (std::exception& e) {
    throw PasswordError();
  }

  std::array<uint8_t, 32> content_start_bytes_tst;
  content.read(reinterpret_cast<char*>(content_start_bytes_tst.data()),
               content_start_bytes_tst.size());
  if (!content.good() || content_start_bytes != content_start_bytes_tst)
    throw PasswordError();

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256,
                db->inner_random_stream_key().data(),
                db->inner_random_stream_key().size());
  SHA256_Final(final_inner_random_stream_key.data(), &sha256);
  RandomObfuscator obfuscator(final_inner_random_stream_key,
                              kKdbxInnerRandomStreamInitVec);

  // Parse XML content.
  hashed_istreambuf hashed_streambuf(content);
  std::istream hashed_stream(&hashed_streambuf);

  if (db->compress()) {
    gzip_istreambuf gzip_streambuf(hashed_stream);
    std::istream gzip_stream(&gzip_streambuf);

    ParseXml(gzip_stream, obfuscator, *db.get());
  } else {
    ParseXml(hashed_stream, obfuscator, *db.get());
  }

  // Validate header hash.
  if (header_hash_ != header_hash)
    throw FormatError("Header checksum error in KDBX.");

  return db;
}

void KdbxFile::Export(const std::string& path, const Database& db,
                      const Key& key) {
  Reset();

  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> transformed_key = key.Transform(
      db.transform_seed(), db.transform_rounds(),
      Key::SubKeyResolution::kHashSubKeys);
  std::array<uint8_t, 32> final_key;

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, db.master_seed().data(), db.master_seed().size());
  SHA256_Update(&sha256, transformed_key.data(), transformed_key.size());
  SHA256_Final(final_key.data(), &sha256);

  assert(db.cipher() == Database::Cipher::kAes);
  std::unique_ptr<Cipher<16>> cipher(
      new AesCipher(final_key, db.init_vector()));

  // Write header to temporary stream so that we can compute the hash of it.
  KdbxHeader header;
  header.signature0 = kKdbxSignature0;
  header.signature1 = kKdbxSignature1;
  header.version = kKdbxVersionCriticalMin;

  std::stringstream header_stream;
  conserve<KdbxHeader>(header_stream, header);

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kCipherId, 16));
  conserve<std::array<uint8_t, 16>>(header_stream, kKdbxCipherAes);

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kCompressionFlags, 4));
  conserve<uint32_t>(header_stream, db.compress() ?
      static_cast<uint32_t>(kKdbxCompressionFlags::kGzip) : 0);

  if (db.master_seed().size() >
      std::numeric_limits<decltype(KdbxHeaderField::size)>::max()) {
    assert(false);
    throw InternalError("Master seed size exceeds KDBX maximum.");
  }
  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kMasterSeed, db.master_seed().size()));
  conserve<std::vector<uint8_t>>(header_stream, db.master_seed());

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kTransformSeed, 32));
  conserve<std::array<uint8_t, 32>>(header_stream, db.transform_seed());

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kTransformRounds, 8));
  conserve<uint64_t>(header_stream, db.transform_rounds());

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kExcryptionInitVec, 16));
  conserve<std::array<uint8_t, 16>>(header_stream, db.init_vector());

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kInnerRandomStreamKey, 32));
  conserve<std::array<uint8_t, 32>>(header_stream,
      db.inner_random_stream_key());

  std::array<uint8_t, 32> content_start_bytes = random_array<32>();
  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kContentStreamStartBytes, 32));
  conserve<std::array<uint8_t, 32>>(header_stream, content_start_bytes);

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kInnerRandomStreamId, 4));
  conserve<uint32_t>(header_stream,
      static_cast<uint32_t>(kKdbxRandomStream::kSalsa20));

  conserve<KdbxHeaderField>(header_stream, KdbxHeaderField(
      KdbxHeaderField::kEndOfHeader, 0));

  // Compute the header hash.
  std::string header_data = header_stream.str();
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, header_data.c_str(), header_data.size());
  SHA256_Final(header_hash_.data(), &sha256);

  // Write header to file.
  std::copy(std::istreambuf_iterator<char>(header_stream),
            std::istreambuf_iterator<char>(),
            std::ostreambuf_iterator<char>(dst));

  // Prepare deobfuscation stream.
  std::array<uint8_t, 32> final_inner_random_stream_key;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256,
                db.inner_random_stream_key().data(),
                db.inner_random_stream_key().size());
  SHA256_Final(final_inner_random_stream_key.data(), &sha256);
  RandomObfuscator obfuscator(final_inner_random_stream_key,
                              kKdbxInnerRandomStreamInitVec);

  // Write content to content stream.
  std::stringstream content_stream;
  conserve<std::array<uint8_t, 32>>(content_stream, content_start_bytes);

  hashed_ostreambuf hashed_streambuf(content_stream);
  std::ostream hashed_stream(&hashed_streambuf);

  if (db.compress()) {
    gzip_ostreambuf gzip_streambuf(hashed_stream);
    std::ostream gzip_stream(&gzip_streambuf);

    WriteXml(gzip_stream, obfuscator, db);
    gzip_stream.flush();
  } else {
    WriteXml(hashed_stream, obfuscator, db);
  }

  hashed_stream.flush();

  // Encrypt content.
  encrypt_cbc(content_stream, dst, *cipher);
}

}   // namespace keepass
