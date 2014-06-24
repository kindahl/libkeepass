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

class Icon;

class Group final {
 private:
  std::array<uint8_t, 16> uuid_;
  uint32_t icon_ = 0;
  std::weak_ptr<Icon> custom_icon_;
  std::string name_;
  std::string notes_;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t access_time_ = 0;
  std::time_t expiry_time_ = 0;
  std::time_t move_time_ = 0;
  uint16_t flags_ = 0;
  bool expires_ = false;
  bool expanded_ = false;
  uint32_t usage_count_ = 0;
  std::string default_autotype_sequence_;
  bool autotype_ = false;
  bool search_ = false;
  std::weak_ptr<Entry> last_visible_entry_;

  std::vector<std::shared_ptr<Group>> groups_;
  std::vector<std::shared_ptr<Entry>> entries_;

 public:
  Group();

  const std::array<uint8_t, 16>& uuid() const { return uuid_; }
  void set_uuid(const std::array<uint8_t, 16>& uuid) { uuid_ = uuid; }

  uint32_t icon() const { return icon_; }
  void set_icon(const uint32_t& icon) { icon_ = icon; }

  std::weak_ptr<Icon> custom_icon() const { return custom_icon_; }
  void set_custom_icon(std::weak_ptr<Icon> icon) { custom_icon_ = icon; }

  const std::string& name() const { return name_; }
  void set_name(const std::string& name) { name_ = name; }

  const std::string& notes() const { return notes_; }
  void set_notes(const std::string& notes) { notes_ = notes; }

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

  std::time_t move_time() const { return move_time_; }
  void set_move_time(const std::time_t& time) { move_time_ = time; }

  uint16_t flags() const { return flags_; }
  void set_flags(const uint16_t& flags) { flags_ = flags; }

  bool expires() const { return expires_; }
  void set_expires(bool expires) { expires_ = expires; }

  bool expanded() const { return expanded_; }
  void set_expanded(bool expanded) { expanded_ = expanded; }

  uint32_t usage_count() const { return usage_count_; }
  void set_usage_count(uint32_t usage_count) { usage_count_ = usage_count; }

  const std::string& default_autotype_sequence() const {
    return default_autotype_sequence_;
  }
  void set_default_autotype_sequence(std::string sequence) {
    default_autotype_sequence_ = sequence;
  }

  bool autotype() const { return autotype_; }
  void set_autotype(bool autotype) { autotype_ = autotype; }

  bool search() const { return search_; }
  void set_search(bool search) { search_ = search; }

  std::weak_ptr<Entry> last_visible_entry() const {
    return last_visible_entry_;
  }
  void set_last_visible_entry(std::weak_ptr<Entry> entry) {
    last_visible_entry_ = entry;
  }

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
