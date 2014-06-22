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

namespace keepass {

class Icon final {
 private:
  std::string data_;

 public:
  Icon(const std::string& data) :
      data_(data) {}

  const std::string& data() const { return data_; }
  void set_data(const std::string& data) { data_ = data; }

  bool operator==(const Icon& other) const {
    return data_ == other.data_;
  }
  bool operator!=(const Icon& other) const {
    return !(*this == other);
  }
};

}   // namespace keepass
