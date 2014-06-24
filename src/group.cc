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

#include "group.hh"

#include <sstream>

#include "util.hh"

namespace keepass {

Group::Group() :
    uuid_(generate_uuid()) {
}

const std::vector<std::shared_ptr<Group>>& Group::Groups() const {
  return groups_;
}

const std::vector<std::shared_ptr<Entry>>& Group::Entries() const {
  return entries_;
}

void Group::AddGroup(std::shared_ptr<Group> group) {
  groups_.push_back(group);
}

void Group::AddEntry(std::shared_ptr<Entry> entry) {
  entries_.push_back(entry);
}

bool Group::HasNonMetaEntries() const {
  return std::find_if(entries_.begin(), entries_.end(),
      [](const std::shared_ptr<Entry>& entry) {
        return !entry->IsMetaEntry();
      }) != entries_.end();
}

std::string Group::ToJson() const {
  std::stringstream json;

  json << "{";
  json << "\"icon\":" << icon_;
  if (custom_icon_.lock())
    json << ",\"custom_icon\":\"" << true << "\"";
  if (!name_.empty())
    json << ",\"name\":\"" << name_ << "\"";
  if (!notes_.empty())
    json << ",\"notes\":\"" << notes_ << "\"";
  if (creation_time_ != 0)
    json << ",\"creation_time\":\"" << time_to_str(creation_time_) << "\"";
  if (modification_time_ != 0) {
    json << ",\"modification_time\":\"" << time_to_str(modification_time_) <<
        "\"";
  }
  if (access_time_ != 0)
    json << ",\"access_time\":\"" << time_to_str(access_time_) << "\"";
  if (expiry_time_ != 0)
    json << ",\"expiry_time\":\"" << time_to_str(expiry_time_) << "\"";
  if (move_time_ != 0)
    json << ",\"move_time\":\"" << time_to_str(move_time_) << "\"";
  if (flags_ != 0)
    json << ",\"flags\":" << flags_;
  if (!groups_.empty()) {
    json << ",\"groups\":[";

    std::string sep;
    for (auto it = groups_.begin(); it != groups_.end(); ++it) {
      json << sep << (*it)->ToJson();
      sep = ",";
    }

    json << "]";
  }
  if (HasNonMetaEntries()) {
    json << ",\"entries\":[";

    std::string sep;
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      const auto& entry = *it;
      if (entry->IsMetaEntry())
        continue;

      json << sep << entry->ToJson();
      sep = ",";
    }

    json << "]";
  }
  json << "}";

  return json.str();
}

bool Group::operator==(const Group& other) const {
  return uuid_ == other.uuid_ &&
      icon_ == other.icon_ &&
      custom_icon_.lock() == other.custom_icon_.lock() &&
      name_ == other.name_ &&
      notes_ == other.notes_ &&
      creation_time_ == other.creation_time_ &&
      modification_time_ == other.modification_time_ &&
      access_time_ == other.access_time_ &&
      expiry_time_ == other.expiry_time_ &&
      move_time_ == other.move_time_ &&
      flags_ == other.flags_ &&
      expires_ == other.expires_ &&
      expanded_ == other.expanded_ &&
      usage_count_ == other.usage_count_ &&
      default_autotype_sequence_ == other.default_autotype_sequence_ &&
      autotype_ == other.autotype_ &&
      search_ == other.search_ &&
      last_visible_entry_.lock() == other.last_visible_entry_.lock() &&
      indirect_equal<std::shared_ptr<Group>>(groups_, other.groups_) &&
      indirect_equal<std::shared_ptr<Entry>>(entries_, other.entries_);
}

bool Group::operator!=(const Group& other) const {
  return !(*this == other);
}

}   // namespace keepass
