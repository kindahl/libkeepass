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

#include <iostream>

#include "kdb.hh"
#include "kdbx.hh"
#include "key.hh"

using namespace keepass;

int main(int argc, const char * argv[]) {
  if (argc != 2) {
    std::cerr << "error: invalid usage." << std::endl;
    return 1;
  }

  try {
    Key key("password");

    bool kdbx = true;   // Assume KDBX by default.

    // Check if KDB file.
    std::string path = argv[1];
    std::size_t ext_delim = path.rfind('.');
    if (ext_delim != std::string::npos) {
      if (path.substr(ext_delim, path.size() - ext_delim) == ".kdb")
        kdbx = false;
    }

    if (kdbx) {
      KdbxFile file;
      std::cout << file.Import(path, key)->root().lock()->ToJson() <<
          std::endl;
    } else {
      KdbFile file;
      std::cout << file.Import(path, key)->root().lock()->ToJson() <<
          std::endl;
    }
  } catch (std::runtime_error& e) {
    std::cerr << "error: " << e.what() << std::endl;
  }

  return 0;
}
