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

#include "util.hh"

namespace keepass {

template<>
std::string consume<std::string>(std::istream& src) {
  // Don't read the stream into a string directly. We want to make sure that we
  // get a clean string.
  std::vector<char> str_data;
  std::copy(std::istreambuf_iterator<char>(src), 
            std::istreambuf_iterator<char>(), 
            std::back_inserter(str_data));

  if (str_data.size() == 0)
    throw std::runtime_error("cannot consume string of zero length.");

  std::string str;
  str.reserve(str_data.size());
  for (char c : str_data) {
    if (c == '\0')
      break;
    str.push_back(c);
  }

  return str;
}

template <>
std::vector<char> consume<std::vector<char>>(std::istream& src) {
  std::vector<char> data;
  std::copy(std::istreambuf_iterator<char>(src),
            std::istreambuf_iterator<char>(),
            std::back_inserter(data));

  return data;
}

template <>
void conserve<std::string>(std::ostream& dst, const std::string& val) {
  dst.write(val.c_str(), val.size() + 1);   // FIXME: Is this safe?
}

template <>
void conserve<std::vector<char>>(std::ostream& dst,
                                 const std::vector<char>& val) {
  dst.write(&val[0], val.size());
}

std::string time_to_str(const std::time_t &time) {
  const std::tm* local_time = std::localtime(&time);
  assert(local_time != nullptr);

  char buffer[128];
  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local_time);
  return buffer;
}

}   // namespace keepass
