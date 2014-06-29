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
#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "exception.hh"

namespace keepass {

template <typename T>
inline T consume(std::istream& src) {
  T val;
  src.read(reinterpret_cast<char *>(&val), sizeof(T));
  if (!src.good())
    throw IoError("Read error.");

  return val;
}

template <>
std::string consume<std::string>(std::istream& src);

template <>
std::vector<char> consume<std::vector<char>>(std::istream& src);

template <>
std::vector<uint8_t> consume<std::vector<uint8_t>>(std::istream& src);

template<typename T>
void conserve(std::ostream& dst, const T& val) {
  dst.write(reinterpret_cast<const char*>(&val), sizeof(T));
}

template <>
void conserve<std::string>(std::ostream& dst, const std::string& val);

template <>
void conserve<std::vector<char>>(std::ostream& dst,
                                 const std::vector<char>& val);
template <>
void conserve<std::vector<uint8_t>>(std::ostream& dst,
                                    const std::vector<uint8_t>& val);

}   // namespace keepass
