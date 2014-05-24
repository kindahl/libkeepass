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

namespace keepass {

class Key final {
 private:
  const std::array<uint8_t, 32> key_ = { { 0 } };

 public:
  Key(const std::string& password);
  Key(const std::vector<uint8_t>& password);

  std::array<uint8_t, 32> Transform(const std::array<uint8_t, 32>& seed,
                                    const uint32_t rounds) const;
};

}
