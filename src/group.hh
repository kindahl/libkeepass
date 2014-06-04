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
#include <ctime>
#include <memory>
#include <vector>

#include "entry.hh"

namespace keepass {

class Group final {
 private:
  std::string name_;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t access_time_ = 0;
  std::time_t expiry_time_ = 0;
  uint32_t icon_ = 0;
  uint16_t flags_ = 0;

  std::vector<std::shared_ptr<Group>> groups_;
  std::vector<std::shared_ptr<Entry>> entries_;

 public:
  const std::string& name() const { return name_; }
  void set_name(const std::string& name) { name_ = name; }

  std::time_t creation_time() const { return creation_time_; }
  void set_creation_time(const std::time_t& time) { creation_time_ = time; }

  std::time_t modification_time() const { return modification_time_; }
  void set_modification_time(const std::time_t& time) {
    modification_time_ = time;
  }

  std::time_t access_time() const { return access_time_; }
  void set_access_time(const std::time_t& time) { access_time_ = time; }

  std::time_t expiry_time() const { return expiry_time_; }
  void set_expiry_time(const std::time_t& time) { expiry_time_ = time; }

  uint32_t icon() const { return icon_; }
  void set_icon(const uint32_t& icon) { icon_ = icon; }

  uint16_t flags() const { return flags_; }
  void set_flags(const uint16_t& flags) { flags_ = flags; }

  const std::vector<std::shared_ptr<Group>>& Groups() const;
  const std::vector<std::shared_ptr<Entry>>& Entries() const;

  void AddGroup(std::shared_ptr<Group> group);
  void AddEntry(std::shared_ptr<Entry> entry);

  bool HasNonMetaEntries() const;

  std::string ToJson() const;

  bool operator==(const Group& other) const;
  bool operator!=(const Group& other) const;
};

}   // namespace keepass
