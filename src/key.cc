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

#include "key.hh"

#include <algorithm>
#include <fstream>
#include <memory>

#include <openssl/sha.h>

#include "base64.hh"
#include "cipher.hh"
#include "exception.hh"
#include "pugixml.hh"

namespace keepass {

std::array<uint8_t, 32> Key::CompositeKey::Resolve(
    SubKeyResolution resolution) const {
  static const std::array<uint8_t, 32> kEmptyKey = { { 0 } };

  if (resolution == SubKeyResolution::kHashSubKeys) {
      std::array<uint8_t, 32> key;

      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      if (password_key_ != kEmptyKey)
          SHA256_Update(&sha256, password_key_.data(), password_key_.size());
      if (keyfile_key_ != kEmptyKey)
          SHA256_Update(&sha256, keyfile_key_.data(), keyfile_key_.size());
      SHA256_Final(key.data(), &sha256);

      return key;
  } else {
    if (password_key_ != kEmptyKey) {
      if (keyfile_key_ != kEmptyKey) {
        std::array<uint8_t, 32> key;

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password_key_.data(), password_key_.size());
        SHA256_Update(&sha256, keyfile_key_.data(), keyfile_key_.size());
        SHA256_Final(key.data(), &sha256);

        return key;
      } else {
        return password_key_;
      }
    } else {
      return keyfile_key_;
    }
  }
}

Key::Key(const std::string& password) {
  SetPassword(password);
}

void Key::SetPassword(const std::string& password) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, reinterpret_cast<const uint8_t*>(password.c_str()),
                password.size());
  SHA256_Final(key_.password_key_.data(), &sha256);
}

void Key::SetKeyFile(const std::string& path) {
  std::ifstream src(path, std::ios::in | std::ios::binary);
  if (!src.is_open())
    throw FileNotFoundError();

  // First, try to parse the key file as XML.
  pugi::xml_document doc;
  if (doc.load(src, pugi::parse_default | pugi::parse_trim_pcdata)) {
    std::string key_str = base64_decode(
        doc.child("KeyFile").child("Key").child_value("Data"));
    if (key_str.size() != 32)
      throw FormatError("Invalid key size in key file.");

    std::copy(key_str.begin(), key_str.end(), key_.keyfile_key_.begin());
    return;
  }

  // If not XML, reset stream and try to parse as text.
  src.seekg(0, std::ios::beg);

  std::vector<char> data;
  std::copy(std::istreambuf_iterator<char>(src), 
            std::istreambuf_iterator<char>(), 
            std::back_inserter(data));
  if (data.size() != 64)
    throw FormatError("Unknown key file format.");

  for (std::size_t i = 0; i < key_.keyfile_key_.size(); ++i) {
    char c[2] = { data[i * 2], data[i * 2 + 1] };

    if (!std::isxdigit(c[0]) || !std::isxdigit(c[1]))
      throw FormatError("Unknown key file format.");

    uint8_t v = std::stoi(std::string(c, 2), 0, 16);
    key_.keyfile_key_[i] = v;
  }
}

std::array<uint8_t, 32> Key::Transform(const std::array<uint8_t, 32>& seed,
                                       const uint64_t rounds,
                                       SubKeyResolution resolution) const {
  AesCipher cipher(seed);

  std::array<uint8_t, 32> transformed_key = key_.Resolve(resolution);
  for (uint32_t i = 0; i < rounds; ++i)
    transformed_key = encrypt_ecb(transformed_key, cipher);

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, transformed_key.data(), transformed_key.size());
  SHA256_Final(transformed_key.data(), &sha256);

  return transformed_key;
}

}   // namespace keepass
