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
#include <memory>

#include "group.hh"

namespace keepass {

class Database final {
 public:
  enum class Cipher {
    kAes,
    kTwoFish
  };

 private:
  std::shared_ptr<Group> root_;
  Cipher cipher_ = Cipher::kAes;
  std::array<uint8_t, 16> master_seed_;
  std::array<uint8_t, 16> init_vector_;
  std::array<uint8_t, 32> transform_seed_;
  uint32_t transform_rounds_ = 8192;

 public:
  std::weak_ptr<Group> root() const { return root_; }
  void set_root(std::shared_ptr<Group> root) { root_ = root; }

  Cipher cipher() const { return cipher_; }
  void set_cipher(Cipher cipher) { cipher_ = cipher; }

  const std::array<uint8_t, 16>& master_seed() const { return master_seed_; }
  void set_master_seed(std::array<uint8_t, 16>& master_seed) {
    master_seed_ = master_seed;
  }

  const std::array<uint8_t, 16>& init_vector() const { return init_vector_; }
  void set_init_vector(std::array<uint8_t, 16>& init_vector) {
    init_vector_ = init_vector;
  }

  const std::array<uint8_t, 32>& transform_seed() const {
    return transform_seed_;
  }
  void set_transform_seed(std::array<uint8_t, 32>& transform_seed) {
    transform_seed_ = transform_seed;
  }

  uint32_t transform_rounds() const { return transform_rounds_; }
  void set_transform_rounds(uint32_t transform_rounds) {
    transform_rounds_ = transform_rounds;
  }
};

}   // namespace keepass
