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
#include <string>

#include "security.hh"

namespace keepass {

class Binary final {
 private:
  protect<std::string> data_;
  bool compress_ = false;

 public:
  Binary(const protect<std::string>& data) :
      data_(data) {}

  bool Empty() const { return data_->empty(); }
  std::size_t Size() const { return data_->size(); }

  const protect<std::string>& data() const { return data_; }
  void set_data(const protect<std::string>& data) { data_ = data; }

  bool compress() const { return compress_; }
  void set_compress(bool compress) { compress_ = compress; }

  bool operator==(const Binary& other) const {
    return data_ == other.data_;
  }
  bool operator!=(const Binary& other) const {
    return !(*this == other);
  }
};

}   // namespace keepass
