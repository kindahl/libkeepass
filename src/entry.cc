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

#include "entry.hh"

#include <sstream>

#include "util.hh"

namespace keepass {

std::string Entry::Attachment::ToJson() const {
  std::stringstream json;

  json << "{";
  if (!name_.empty())
    json << "\"name\":\"" << name_ << "\"";
  if (!data_.empty()) {
    json << (name_.empty() ? "" : ",") << "\"data\":\"" <<
        std::string(data_.begin(), data_.end()) << "\"";
  }
  json << "}";

  return json.str();
}

bool Entry::HasAttachment() const {
  return attachment_.get();
}

bool Entry::IsMetaEntry() const {
  return title_ == "Meta-Info" && url_ == "$" && username_ == "SYSTEM" &&
      !notes_.empty() && attachment_ && attachment_->name() == "bin-stream";
}

std::string Entry::ToJson() const {
  std::stringstream json;

  json << "{";
  json << "\"icon\":" << icon_;
  if (!title_.empty())
    json << ",\"title\":\"" << title_ << "\"";
  if (!url_.empty())
    json << ",\"url\":\"" << url_ << "\"";
  if (!username_.empty())
    json << ",\"username\":\"" << username_ << "\"";
  if (!password_.empty())
    json << ",\"password\":\"" << password_ << "\"";
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
  if (attachment_)
    json << ",\"attachment\":" << attachment_->ToJson();
  json << "}";

  return json.str();
}

bool Entry::operator==(const Entry& other) const {
  if (uuid_ != other.uuid_ ||
      icon_ != other.icon_ ||
      title_ != other.title_ ||
      url_ != other.url_ ||
      username_ != other.username_ ||
      password_ != other.password_ ||
      notes_ != other.notes_ ||
      creation_time_ != other.creation_time_ ||
      modification_time_ != other.modification_time_ ||
      access_time_ != other.access_time_ ||
      expiry_time_ != other.expiry_time_) {
    return false;
  }

  if (HasAttachment() != other.HasAttachment())
    return false;

  if (attachment_ && *attachment_.get() != *other.attachment_.get())
    return false;

  return true;
}

bool Entry::operator!=(const Entry& other) const {
  return !(*this == other);
}

}   // namespace keepass
