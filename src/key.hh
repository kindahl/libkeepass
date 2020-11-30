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

#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace keepass {

class Key final {
 public:
  /**
   * Strategies for how to resolve sub keys before applying the
   * transformation.
   */
  enum class SubKeyResolution {
    /** All sub keys will be hashed together into a single hash. Single sub
     * keys will be hashed despite not being part of a composite key. */
    kHashSubKeys,

    /** All sub keys will be hashed together into a single hash. If there is
     * only a single sub key, that sub key will be processed as is without any
     * additional hashing. */
    kHashSubKeysOnlyIfCompositeKey
  };

 private:
  struct CompositeKey {
    std::array<uint8_t, 32> password_key_ = { { 0 } };
    std::array<uint8_t, 32> keyfile_key_ = { { 0 } };

    std::array<uint8_t, 32> Resolve(SubKeyResolution resolution) const;
  } key_;

 public:
  Key() = default;
  Key(const std::string& password);

  void SetPassword(const std::string& password);
  void SetKeyFile(const std::string& path);

  std::array<uint8_t, 32> Transform(const std::array<uint8_t, 32>& seed,
                                    const uint64_t rounds,
                                    SubKeyResolution resolution) const;
};

}
