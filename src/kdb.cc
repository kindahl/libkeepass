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
#include "format.hh"
#include "group.hh"
#include "key.hh"
#include "util.hh"

namespace keepass {

const uint32_t kKdbSignature0 = 0x9aa2d903;
const uint32_t kKdbSignature1 = 0xb54bfb65;
const uint32_t kKdbFlagSha2 = 0x00000001;
const uint32_t kKdbFlagRijndael = 0x00000002;
const uint32_t kKdbFlagArcFour = 0x00000004;
const uint32_t kKdbFlagTwoFish = 0x00000008;

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
  std::array<uint8_t, 5> packed;

  std::time_t ToTime() const {
    static const std::array<uint8_t, 5> kNeverTimeConstant = {
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
    if (res == -1)
      throw std::runtime_error("bad time format.");

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
      throw std::runtime_error("unable to read group field.");

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
        throw std::runtime_error("illegal field in group.");
        break;
    }
  }

  throw std::runtime_error("no end-of-fields found in group.");

  return group;
}

std::shared_ptr<Entry> KdbFile::ReadEntry(std::istream& src,
                                          uint32_t& group_id) const {
  std::shared_ptr<Entry> entry = std::make_shared<Entry>();
  std::unique_ptr<Entry::Attachment> attachment;

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
      throw std::runtime_error("unable to read entry field.");

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
        entry->set_title(consume<std::string>(field));
        break;
      case KdbEntryFieldType::kUrl:
        entry->set_url(consume<std::string>(field));
        break;
      case KdbEntryFieldType::kUsername:
        entry->set_username(consume<std::string>(field));
        break;
      case KdbEntryFieldType::kPassword:
        entry->set_password(consume<std::string>(field));
        break;
      case KdbEntryFieldType::kNotes:
        entry->set_notes(consume<std::string>(field));
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
            attachment.reset(new Entry::Attachment());
          attachment->set_name(name);
        break;
      }
      case KdbEntryFieldType::kAttachmentData:
        if (field_size > 0) {
          if (!attachment)
            attachment.reset(new Entry::Attachment());
          attachment->set_data(consume<std::vector<char>>(field));
        }
        break;
      case KdbEntryFieldType::kEnd:
        if (attachment)
          entry->set_attachment(attachment);
        return entry;
      default:
        throw std::runtime_error("illegal field in entry.");
        break;
    }
  }

  throw std::runtime_error("no end-of-fields found in entry.");

  return entry;
}

std::unique_ptr<Database> KdbFile::Import(const std::string& path,
                                          const Key& key) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw std::runtime_error("file not found.");

  // Read header.
  KdbHeader header;
  src.read(reinterpret_cast<char *>(&header), sizeof(header));
  if (!src.good())
    throw std::runtime_error("unable to read file header.");

  if (header.signature0 != kKdbSignature0 ||
      header.signature1 != kKdbSignature1)
    throw std::runtime_error("not a keepass database.");

  switch (header.version & 0xffffff00) {
    // Version 1.
    case 0x00010000:
      throw std::runtime_error("kdb version 1 is not supported.");
      break;
    // Version 2.
    case 0x00020000:
      throw std::runtime_error("kdb version 2 is not supported.");
      break;
    // Version 3.
    case 0x00030000:
      //throw std::runtime_error("kdb version 3 is not supported.");
      break;
    default:
      throw std::runtime_error(
          Format() << "unsupported kdb version: 0x" << header.version << ".");
      break;
  }

  std::unique_ptr<Database> db(new Database());
  db->set_master_seed(header.master_seed);
  db->set_init_vector(header.init_vector);
  db->set_transform_seed(header.transform_seed);
  db->set_transform_rounds(header.transform_rounds);

  // Produce the final key used for decrypting the contents.
  std::array<uint8_t, 32> transformed_key = key.Transform(
      header.transform_seed, header.transform_rounds);
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
  } else if (header.flags & kKdbFlagTwoFish) {
    db->set_cipher(Database::Cipher::kTwoFish);
    throw std::runtime_error("two fish crypto algorithm isn't implemented.");
  } else {
    throw std::runtime_error("illegal crypto algorithm in header.");
  }

  // Decrypt the content.
  std::stringstream content;

  try {
    decrypt_cbc(src, content, *cipher);
  } catch (std::runtime_error& e) {
    throw std::runtime_error("invalid password.");
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
  if (content_hash != header.content_hash) {
    throw std::runtime_error("invalid password.");
  }

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
        throw std::runtime_error("illformed group tree.");

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
      throw std::runtime_error("database contains an orphaned entry.");

    it->second->AddEntry(entry);
  }

  db->set_root(group_root);
  return std::move(db);
}

bool KdbFile::Export(const std::string& path) {
  path.c_str();
  return false;
}

}   // namespace keepass
