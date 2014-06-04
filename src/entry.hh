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
#include <string>
#include <vector>

namespace keepass {

class Entry final {
 public:
  class Attachment final {
   private:
    std::string name_;
    std::vector<char> data_;

   public:
    const std::string& name() const { return name_; }
    void set_name(const std::string& name) { name_ = name; }

    const std::vector<char>& data() const { return data_; }
    void set_data(const std::vector<char>&& data) { data_ = std::move(data); }

    std::string ToJson() const;

    bool operator==(const Attachment& other) const {
      return name_ == other.name_ && data_ == other.data_;
    }
    bool operator!=(const Attachment& other) const {
      return !(*this == other);
    }
  };

 private:
  std::array<uint8_t, 16> uuid_;
  uint32_t icon_ = 0;
  std::string title_;
  std::string url_;
  std::string username_;
  std::string password_;
  std::string notes_;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t access_time_ = 0;
  std::time_t expiry_time_ = 0;
  std::shared_ptr<Attachment> attachment_;

 public:
  const std::array<uint8_t, 16>& uuid() const { return uuid_; }
  void set_uuid(const std::array<uint8_t, 16>& uuid) { uuid_ = uuid; }

  uint32_t icon() const { return icon_; }
  void set_icon(const uint32_t& icon) { icon_ = icon; }

  const std::string& title() const { return title_; }
  void set_title(const std::string& title) { title_ = title; }

  const std::string& url() const { return url_; }
  void set_url(const std::string& url) { url_ = url; }

  const std::string& username() const { return username_; }
  void set_username(const std::string& username) { username_ = username; }

  const std::string& password() const { return password_; }
  void set_password(const std::string& password) { password_ = password; }

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

  std::shared_ptr<Attachment> attachment() const { return attachment_; }
  void set_attachment(std::shared_ptr<Attachment> attachment) {
    attachment_ = attachment;
  }

  bool HasAttachment() const;
  bool IsMetaEntry() const;

  std::string ToJson() const;

  bool operator==(const Entry& other) const;
  bool operator!=(const Entry& other) const;
};

}   // namespace keepass
