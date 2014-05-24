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

#include <memory>

#include <openssl/sha.h>

#include "cipher.hh"

namespace keepass {

Key::Key(const std::string& password) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, reinterpret_cast<const uint8_t*>(password.c_str()),
                password.size());
  SHA256_Final(const_cast<uint8_t*>(key_.data()), &sha256);
}

Key::Key(const std::vector<uint8_t>& password) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, &password[0], password.size());
  SHA256_Final(const_cast<uint8_t*>(key_.data()), &sha256);
}

std::array<uint8_t, 32> Key::Transform(const std::array<uint8_t, 32>& seed,
                                       const uint32_t rounds) const {
  AesCipher cipher(seed);

  std::array<uint8_t, 32> transformed_key = key_;
  for (uint32_t i = 0; i < rounds; ++i)
    transformed_key = encrypt_ecb(transformed_key, cipher);

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, transformed_key.data(), transformed_key.size());
  SHA256_Final(transformed_key.data(), &sha256);

  return transformed_key;
}

}   // namespace keepass
