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

#include "kdb.hh"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <unordered_map>

#include <openssl/sha.h>

#include "cipher.hh"
#include "database.hh"
#include "entry.hh"
#include "exception.hh"
#include "format.hh"
#include "group.hh"
#include "io.hh"
#include "key.hh"
#include "util.hh"

namespace keepass {

const uint32_t kKdbSignature0 = 0x9aa2d903;
const uint32_t kKdbSignature1 = 0xb54bfb65;
const uint32_t kKdbFlagSha2 = 0x00000001;
const uint32_t kKdbFlagRijndael = 0x00000002;
const uint32_t kKdbFlagArcFour = 0x00000004;
const uint32_t kKdbFlagTwofish = 0x00000008;

#pragma pack(push, 1)
struct KdbHeader {
  uint32_t signature0;
  uint32_t signature1;
  uint32_t flags;
  uint32_t version;
  std::array<uint8_t, 16> master_seed;
  std::array<uint8_t, 16> init_vector;
  uint32_t num_groups;
  uint32_t num_entries;
  std::array<uint8_t, 32> content_hash;
  std::array<uint8_t, 32> transform_seed;
  uint32_t transform_rounds;
};
static_assert(sizeof(KdbHeader) == 124,
              "bad packing of header structure.");

/**
 * @brief KDB time entry.
 *
 * Five bytes in a packed format:
 * 00YYYYYY YYYYYYMM MMDDDDDH HHHHMMMM MMSSSSSS
 */
struct KdbTime {
  std::array<uint8_t, 5> packed = { { 0 } };

  KdbTime() = default;

  KdbTime(std::time_t time) {
    static constexpr std::array<uint8_t, 5> kNeverTimeConstant = {
      0x2e, 0xdf, 0x39, 0x7e, 0xfb
    };
    if (time == -1) {
      packed = kNeverTimeConstant;
    } else {
      std::tm* time_ptr = std::localtime(&time);

      uint32_t year = time_ptr->tm_year + 1900;
      uint32_t month = time_ptr->tm_mon + 1;
      uint32_t day = time_ptr->tm_mday;
      uint32_t hour = time_ptr->tm_hour;
      uint32_t minute = time_ptr->tm_min;
      uint32_t second = time_ptr->tm_sec;

      packed[0] = year >> 6;
      packed[1] = ((year & 0x3f) << 2) | (month >> 2);
      packed[2] = ((month & 0x3) << 6) | (day << 1) | (hour >> 4);
      packed[3] = ((hour & 0xf) << 4) | (minute >> 2);
      packed[4] = ((minute & 0x3) << 6) | second;
    }
  }

  std::time_t ToTime() const {
    static constexpr std::array<uint8_t, 5> kNeverTimeConstant = {
      0x2e, 0xdf, 0x39, 0x7e, 0xfb
    };

    // Expand the bytes to 16-bits so that we can shift freely.
    std::array<uint16_t, 5> packed16;
    std::copy(packed.begin(), packed.end(), packed16.begin());

    uint32_t year = (packed16[0] << 6) | (packed16[1] >> 2);
    uint32_t month = ((packed16[1] & 0x0003) << 2) | (packed16[2] >> 6);
    uint32_t day = (packed16[2] >> 1) & 0x001f;
    uint32_t hour = ((packed16[2] & 0x0001) << 4) | (packed16[3] >> 4);
    uint32_t minute = ((packed16[3] & 0x000f) << 2) | (packed16[4] >> 6);
    uint32_t second = packed16[4] & 0x003f;

    if (packed == kNeverTimeConstant)
      return 0;

    assert(second <= 60);
    assert(minute <= 59);
    assert(hour <= 23);
    assert(day >= 1 && day <= 31);
    assert(month >= 1 && month <= 12);
    assert(year >= 1900);

    std::tm time;
    time.tm_sec = second;
    time.tm_min = minute;
    time.tm_hour = hour;
    time.tm_mday = day;
    time.tm_mon = month - 1;    // [0,11]
    time.tm_year = year - 1900;
    time.tm_wday = 0;   // Ignored by std::mktime().
    time.tm_yday = 0;   // Ignored by std::mktime().
    time.tm_isdst = -1;

    std::time_t res = std::mktime(&time);
    if (res == -1) {
      assert(false);
      return 0;
    }

    return res;
  }
};
static_assert(sizeof(KdbTime) == 5, "bad packing of time structure.");
#pragma pack(pop)

enum class KdbGroupFieldType : uint16_t {
  kEmpty,               ///< 0 bytes.
  kId,                  ///< 4 bytes.
  kName,                ///< N bytes.
  kCreationTime,        ///< 5 bytes.
  kModificationTime,    ///< 5 bytes.
  kAccessTime,          ///< 5 bytes.
  kExpiryTime,          ///< 5 bytes.
  kIcon,                ///< 4 bytes.
  kLevel,               ///< 2 bytes.
  kFlags,               ///< 2 bytes.
  kEnd = 0xffff         ///< 0 bytes.
};

enum class KdbEntryFieldType : uint16_t {
  kEmpty,               ///< 0 bytes.
  kUuid,                ///< 16 bytes.
  kGroupId,             ///< 4 bytes.
  kIcon,                ///< 4 bytes.
  kTitle,               ///< N bytes.
  kUrl,                 ///< N bytes.
  kUsername,            ///< N bytes.
  kPassword,            ///< N bytes.
  kNotes,               ///< N bytes.
  kCreationTime,        ///< 5 bytes.
  kModificationTime,    ///< 5 bytes.
  kAccessTime,          ///< 5 bytes.
  kExpiryTime,          ///< 5 bytes.
  kAttachmentName,      ///< N bytes.
  kAttachmentData,      ///< N bytes.
  kEnd = 0xffff
};

std::shared_ptr<Group> KdbFile::ReadGroup(std::istream& src, uint32_t& id,
                                          uint16_t& level) const {
  std::shared_ptr<Group> group = std::make_shared<Group>();

  while (src.good()) {
    uint16_t field_type = consume<uint16_t>(src);
    uint32_t field_size = consume<uint32_t>(src);

    // Read the complete group field into a separate buffer before parsing.
    // This is to guard against reading outside the field as well as for making
    // sure to read the complete field regardless of how much of it that we
    // parse.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field),
                    field_size,
                    [&src]() { return src.get(); });
    if (!src.good())
      throw IoError("Read error.");

    assert(field.str().size() == field_size);

    // Parse the group field.
    switch (static_cast<KdbGroupFieldType>(field_type)) {
      case KdbGroupFieldType::kEmpty:
        break;
      case KdbGroupFieldType::kId:
        id = consume<uint32_t>(field);
        break;
      case KdbGroupFieldType::kName:
        group->set_name(consume<std::string>(field));
        break;
      case KdbGroupFieldType::kCreationTime:
        group->set_creation_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbGroupFieldType::kModificationTime:
        group->set_modification_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbGroupFieldType::kAccessTime:
        group->set_access_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbGroupFieldType::kExpiryTime:
        group->set_expiry_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbGroupFieldType::kIcon:
        group->set_icon(consume<uint32_t>(field));
        break;
      case KdbGroupFieldType::kLevel:
        level = consume<uint16_t>(field);
        break;
      case KdbGroupFieldType::kFlags:
        group->set_flags(consume<uint16_t>(field));
        break;
      case KdbGroupFieldType::kEnd:
        return group;
      default:
        throw FormatError("Illegal group field in KDB.");
        break;
    }
  }

  throw FormatError("Missing EOF in KDB group.");
  return group;
}

void KdbFile::WriteGroup(std::ostream& dst, std::shared_ptr<Group> group,
                         uint32_t group_id, uint16_t level) const {
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kId));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, group_id);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kName));
  conserve<uint32_t>(dst, group->name().size() + 1);
  conserve<std::string>(dst, group->name());

  KdbTime creation_time(group->creation_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kCreationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, creation_time);

  KdbTime modification_time(group->modification_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kModificationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, modification_time);

  KdbTime access_time(group->access_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kAccessTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, access_time);

  KdbTime expiry_time(group->expiry_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kExpiryTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, expiry_time);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kIcon));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, group->icon());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kLevel));
  conserve<uint32_t>(dst, 2);
  conserve<uint16_t>(dst, level);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kFlags));
  conserve<uint32_t>(dst, 2);
  conserve<uint16_t>(dst, group->flags());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbGroupFieldType::kEnd));
  conserve<uint32_t>(dst, 0);
}

std::shared_ptr<Entry> KdbFile::ReadEntry(std::istream& src,
                                          uint32_t& group_id) const {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();
  std::shared_ptr<Entry::Attachment> attachment;

  while (src.good()) {
    uint16_t field_type = consume<uint16_t>(src);
    uint32_t field_size = consume<uint32_t>(src);

    // Read the complete entry field into a separate buffer before parsing.
    // This is to guard against reading outside the field as well as for making
    // sure to read the complete field regardless of how much of it that we
    // parse.
    std::stringstream field;
    std::generate_n(std::ostreambuf_iterator<char>(field),
                    field_size,
                    [&src]() { return src.get(); });
    if (!src.good())
      throw IoError("Read error.");

    assert(field.str().size() == field_size);

    // Parse the entry field.
    switch (static_cast<KdbEntryFieldType>(field_type)) {
      case KdbEntryFieldType::kEmpty:
        break;
      case KdbEntryFieldType::kUuid:
        entry->set_uuid(consume<std::array<uint8_t, 16>>(field));
        break;
      case KdbEntryFieldType::kGroupId:
        group_id = consume<uint32_t>(field);
        break;
      case KdbEntryFieldType::kIcon:
        entry->set_icon(consume<uint32_t>(field));
        break;
      case KdbEntryFieldType::kTitle:
        entry->set_title(protect<std::string>(
            consume<std::string>(field), false));
        break;
      case KdbEntryFieldType::kUrl:
        entry->set_url(protect<std::string>(
            consume<std::string>(field), false));
        break;
      case KdbEntryFieldType::kUsername:
        entry->set_username(protect<std::string>(
            consume<std::string>(field), false));
        break;
      case KdbEntryFieldType::kPassword:
        entry->set_password(protect<std::string>(
            consume<std::string>(field), false));
        break;
      case KdbEntryFieldType::kNotes:
        entry->set_notes(protect<std::string>(
            consume<std::string>(field), false));
        break;
      case KdbEntryFieldType::kCreationTime:
        entry->set_creation_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbEntryFieldType::kModificationTime:
        entry->set_modification_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbEntryFieldType::kAccessTime:
        entry->set_access_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbEntryFieldType::kExpiryTime:
        entry->set_expiry_time(consume<KdbTime>(field).ToTime());
        break;
      case KdbEntryFieldType::kAttachmentName: {
          std::string name = consume<std::string>(field);
          // Keepass 1.x seems to add attachment name fields with only a
          // NULL-character when unused.
          if (name.empty())
            continue;

          if (!attachment)
            attachment = std::make_shared<Entry::Attachment>();
          attachment->set_name(name);
        break;
      }
      case KdbEntryFieldType::kAttachmentData:
        if (field_size > 0) {
          if (!attachment)
            attachment = std::make_shared<Entry::Attachment>();

          std::vector<char> data = consume<std::vector<char>>(field);

          std::shared_ptr<Binary> binary = std::make_shared<Binary>(
              protect<std::string>(std::string(data.begin(), data.end()), false));
          attachment->set_binary(binary);
        }
        break;
      case KdbEntryFieldType::kEnd:
        if (attachment)
          entry->AddAttachment(attachment);
        return entry;
      default:
        throw FormatError("Illegal entry field in KDB.");
        break;
    }
  }

  throw FormatError("Missing EOF in KDB entry.");
  return entry;
}

void KdbFile::WriteEntry(std::ostream& dst,
                         std::shared_ptr<Entry> entry,
                         uint32_t group_id) const {
  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kUuid));
  conserve<uint32_t>(dst, 16);
  conserve<std::array<uint8_t, 16>>(dst, entry->uuid());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kGroupId));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, group_id);

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kIcon));
  conserve<uint32_t>(dst, 4);
  conserve<uint32_t>(dst, entry->icon());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kTitle));
  conserve<uint32_t>(dst, entry->title()->size() + 1);
  conserve<std::string>(dst, entry->title());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kUrl));
  conserve<uint32_t>(dst, entry->url()->size() + 1);
  conserve<std::string>(dst, entry->url());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kUsername));
  conserve<uint32_t>(dst, entry->username()->size() + 1);
  conserve<std::string>(dst, entry->username());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kPassword));
  conserve<uint32_t>(dst, entry->password()->size() + 1);
  conserve<std::string>(dst, entry->password());

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kNotes));
  conserve<uint32_t>(dst, entry->notes()->size() + 1);
  conserve<std::string>(dst, entry->notes());

  KdbTime creation_time(entry->creation_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(
      KdbEntryFieldType::kCreationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, creation_time);

  KdbTime modification_time(entry->modification_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(
      KdbEntryFieldType::kModificationTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, modification_time);

  KdbTime access_time(entry->access_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(
      KdbEntryFieldType::kAccessTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, access_time);

  KdbTime expiry_time(entry->expiry_time());
  conserve<uint16_t>(dst, static_cast<uint16_t>(
      KdbEntryFieldType::kExpiryTime));
  conserve<uint32_t>(dst, sizeof(KdbTime));
  conserve<KdbTime>(dst, expiry_time);

  if (entry->HasAttachment()) {
    assert(entry->attachments().size() == 1);
    std::shared_ptr<Entry::Attachment> attachment = entry->attachments()[0];
    if (!attachment->name().empty()) {
      conserve<uint16_t>(dst, static_cast<uint16_t>(
          KdbEntryFieldType::kAttachmentName));
      conserve<uint32_t>(dst, attachment->name().size() + 1);
      conserve<std::string>(dst, attachment->name());
    }

    if (!attachment->binary()->Empty()) {
      conserve<uint16_t>(dst, static_cast<uint16_t>(
          KdbEntryFieldType::kAttachmentData));
      conserve<uint32_t>(dst, attachment->binary()->Size());

      std::vector<char> data;
      data.resize(attachment->binary()->Size());
      std::copy(attachment->binary()->data()->begin(),
                attachment->binary()->data()->end(),
                data.begin());
      conserve<std::vector<char>>(dst, data);
    }
  }

  conserve<uint16_t>(dst, static_cast<uint16_t>(KdbEntryFieldType::kEnd));
  conserve<uint32_t>(dst, 0);
}

std::unique_ptr<Database> KdbFile::Import(const std::string& path,
                                          const Key& key) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  // Read header.
  KdbHeader header;
  try {
    header = consume<KdbHeader>(src);
  } catch (std::exception& e) {
    throw FormatError("Not a KDB database.");
  }
  if (header.signature0 != kKdbSignature0 ||
      header.signature1 != kKdbSignature1)
    throw FormatError("Not a KDB database.");

  switch (header.version & 0xffffff00) {
    // Version 1.
    case 0x00010000:
      throw FormatError("KDB version 1 is not supported.");
      break;
    // Version 2.
    case 0x00020000:
      throw FormatError("KDB version 2 is not supported.");
      break;
    // Version 3.
    case 0x00030000:
      break;
    default:
      throw FormatError(
          Format() << "Unknown KDB version " << header.version << ".");
      break;
  }

  std::unique_ptr<Database> db(new Database());
  db->set_master_seed(header.master_seed);
  db->set_init_vector(header.init_vector);
  db->set_transform_seed(header.transform_seed);
  db->set_transform_rounds(header.transform_rounds);

  // Produce the final key used for decrypting the contents.
  std::array<uint8_t, 32> transformed_key = key.Transform(
      header.transform_seed, header.transform_rounds,
      Key::SubKeyResolution::kHashSubKeysOnlyIfCompositeKey);
  std::array<uint8_t, 32> final_key;

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, header.master_seed.data(), header.master_seed.size());
  SHA256_Update(&sha256, transformed_key.data(), transformed_key.size());
  SHA256_Final(final_key.data(), &sha256);

  std::unique_ptr<Cipher<16>> cipher;
  if (header.flags & kKdbFlagRijndael) {
    db->set_cipher(Database::Cipher::kAes);

    cipher.reset(new AesCipher(final_key, header.init_vector));
  } else if (header.flags & kKdbFlagTwofish) {
    db->set_cipher(Database::Cipher::kTwofish);

    cipher.reset(new TwofishCipher(final_key, header.init_vector));
  } else {
    throw FormatError("Unknown cipher in KDB.");
  }

  // Decrypt the content.
  std::stringstream content;

  try {
    decrypt_cbc(src, content, *cipher);
  } catch (std::exception& e) {
    throw PasswordError();
  }

  std::array<uint8_t, 32> content_hash;
  SHA256_Init(&sha256);

  uint8_t buffer[1024];
  while (content.good()) {
    content.read(reinterpret_cast<char *>(buffer), sizeof(buffer));
    std::streamsize read_bytes = content.gcount();

    SHA256_Update(&sha256, buffer, read_bytes);
  }

  SHA256_Final(content_hash.data(), &sha256);

  // Reset stream.
  content.clear();
  content.seekg(0, std::ios::beg);

  // Check if contents was successfully decrypted using the specified password.
  if (content_hash != header.content_hash)
    throw PasswordError();

  // Read groups and entries.
  std::vector<std::tuple<std::shared_ptr<Group>, uint16_t>> groups;
  std::unordered_map<uint32_t, std::shared_ptr<Group>> group_map;
  for (decltype(header.num_groups) i = 0; i < header.num_groups; ++i) {
    uint32_t group_id = 0;
    uint16_t group_level = 0;
    std::shared_ptr<Group> group = ReadGroup(content, group_id, group_level);

    groups.push_back(std::make_tuple(group, group_level));
    assert(group_map.count(group_id) == 0);
    group_map[group_id] = group;
  }

  std::vector<std::tuple<std::shared_ptr<Entry>, uint32_t>> entries;
  for (decltype(header.num_entries) i = 0; i < header.num_entries; ++i) {
    uint32_t entry_group_id = 0;
    entries.push_back(std::make_tuple(
        ReadEntry(content, entry_group_id), entry_group_id));
  }

  // Construct the group and entry tree.
  std::shared_ptr<Group> group_root = std::make_shared<Group>();

  uint16_t last_group_level = 0;

  std::vector<std::shared_ptr<Group>> last_group_by_level;
  last_group_by_level.push_back(group_root);

  for (auto& group_data : groups) { 
    std::shared_ptr<Group> group = std::get<0>(group_data);

    // Level of current group plus one, because we have inserted the root at
    // level zero.
    uint16_t group_level = std::get<1>(group_data) + 1;

    if (group_level > last_group_level) {
      if (group_level != last_group_level + 1)
        throw FormatError("Malformed group tree.");

      last_group_by_level[group_level - 1]->AddGroup(group);
      last_group_by_level.push_back(group);
    } else {
      last_group_by_level[group_level - 1]->AddGroup(group);
      last_group_by_level[group_level] = group;
    }

    last_group_level = group_level;
  }

  for (auto& entry_data : entries) {
    std::shared_ptr<Entry> entry = std::get<0>(entry_data);
    uint32_t entry_group_id = std::get<1>(entry_data);

    decltype(group_map)::const_iterator it = group_map.find(entry_group_id);
    if (it == group_map.end())
      throw FormatError("Database contains an orphaned entry.");

    it->second->AddEntry(entry);
  }

  db->set_root(group_root);
  return db;
}

void KdbFile::Export(const std::string& path, const Database& db,
                     const Key& key) {
  // Extract database values in compatible formats.
  assert(db.master_seed().size() == 16);
  std::array<uint8_t, 16> master_seed;
  std::copy(db.master_seed().begin(), db.master_seed().end(),
            master_seed.begin());

  std::ofstream dst(path, std::ios::out | std::ios::binary);
  if (!dst.is_open())
    throw IoError("Unable to open database for writing.");

  // Produce the final key used for encrypting the contents.
  std::array<uint8_t, 32> transformed_key = key.Transform(
      db.transform_seed(), db.transform_rounds(),
      Key::SubKeyResolution::kHashSubKeysOnlyIfCompositeKey);
  std::array<uint8_t, 32> final_key;

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, db.master_seed().data(), db.master_seed().size());
  SHA256_Update(&sha256, transformed_key.data(), transformed_key.size());
  SHA256_Final(final_key.data(), &sha256);

  std::unique_ptr<Cipher<16>> cipher;
  switch (db.cipher()) {
    case Database::Cipher::kAes:
      cipher.reset(new AesCipher(final_key, db.init_vector()));
      break;
    case Database::Cipher::kTwofish:
      cipher.reset(new TwofishCipher(final_key, db.init_vector()));
      break;
    default:
      assert(false);
      break;
  }

  // Write unencrypted content to temporary stream.
  std::stringstream content;
  decltype(KdbHeader::num_groups) num_groups = 0;
  decltype(KdbHeader::num_entries) num_entries = 0;

  dfs<Group, &Group::Groups>(db.root(),
                             [&](const std::shared_ptr<Group>& group,
                                 std::size_t level) {
    if (level > std::numeric_limits<uint16_t>::max()) {
      assert(false);
      throw InternalError("Group hierarchy exceeds KDB maximum.");
    }

    WriteGroup(content, group, num_groups, static_cast<uint16_t>(level));

    if (num_groups == std::numeric_limits<decltype(num_groups)>::max()) {
      assert(false);
      throw InternalError("Group count exceeds KDB maximum.");
    }
    ++num_groups;
  });

  num_groups = 0;
  dfs<Group, &Group::Groups>(db.root(),
                             [&](const std::shared_ptr<Group>& group,
                                 std::size_t) {
    for (const auto entry : group->Entries()) {
      WriteEntry(content, entry, num_groups);

      if (num_entries == std::numeric_limits<decltype(num_entries)>::max()) {
        assert(false);
        throw InternalError("Entry count exceeds KDB maximum.");
      }
      ++num_entries;
    }

    ++num_groups;
  });

  // Compute hash of content stream.
  std::array<uint8_t, 32> content_hash;
  SHA256_Init(&sha256);

  uint8_t buffer[1024];
  while (content.good()) {
    content.read(reinterpret_cast<char *>(buffer), sizeof(buffer));
    std::streamsize read_bytes = content.gcount();

    SHA256_Update(&sha256, buffer, read_bytes);
  }

  SHA256_Final(content_hash.data(), &sha256);

  // Reset stream.
  content.clear();
  content.seekg(0, std::ios::beg);

  // Write header.
  KdbHeader header;
  header.signature0 = kKdbSignature0;
  header.signature1 = kKdbSignature1;
  header.flags = db.cipher() == Database::Cipher::kAes ?
      kKdbFlagRijndael : kKdbFlagTwofish;
  header.version = 0x00030000;
  header.master_seed = master_seed;
  header.init_vector = db.init_vector();
  header.num_groups = num_groups;
  header.num_entries = num_entries;
  header.content_hash = content_hash;
  header.transform_seed = db.transform_seed();
  header.transform_rounds = db.transform_rounds();

  conserve<KdbHeader>(dst, header);

  // Encrypt the content.
  encrypt_cbc(content, dst, *cipher);
}

}   // namespace keepass
