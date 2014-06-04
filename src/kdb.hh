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
#include <cstdint>
#include <memory>
#include <string>

#include "database.hh"

namespace keepass {

class Entry;
class Group;
class Key;

/**
 * @brief Keepass database file representation.
 */
class KdbFile final {
 private:
  std::shared_ptr<Group> ReadGroup(std::istream& src, uint32_t& id,
                                   uint16_t& level) const;
  void WriteGroup(std::ostream& dst, std::shared_ptr<Group> group,
                  uint32_t group_id, uint16_t level) const;

  std::shared_ptr<Entry> ReadEntry(std::istream& src,
                                   uint32_t& group_id) const;
  void WriteEntry(std::ostream& dst, std::shared_ptr<Entry> entry,
                  uint32_t group_id) const;

 public:
  std::unique_ptr<Database> Import(const std::string& path, const Key& key);
  void Export(const std::string& path, const Database& db, const Key& key);
};

}   // namespace keepass
