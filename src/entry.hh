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

#include "binary.hh"
#include "security.hh"
#include "util.hh"

namespace keepass {

class Icon;

class Entry final {
 public:
  class Attachment final {
   private:
    std::string name_;
    std::shared_ptr<Binary> binary_;

   public:
    const std::string& name() const { return name_; }
    void set_name(const std::string& name) { name_ = name; }

    std::shared_ptr<Binary> binary() const { return binary_; }
    void set_binary(std::shared_ptr<Binary> binary) { binary_ = binary; }

    std::string ToJson() const;

    bool operator==(const Attachment& other) const {
      return name_ == other.name_ && indirect_equal(binary_, other.binary_);
    }
    bool operator!=(const Attachment& other) const {
      return !(*this == other);
    }
  };

  class AutoType final {
   public:
    class Association final {
     private:
      std::string window_;
      std::string sequence_;

     public:
      Association(const std::string window, const std::string sequence)
        : window_(window), sequence_(sequence) {}

      const std::string window() const { return window_; }
      const std::string sequence() const { return sequence_; }

      bool operator==(const Association& other) const {
        return window_ == other.window_ && sequence_ == other.sequence_;
      }
      bool operator!=(const Association& other) const {
        return !(*this == other);
      }
    };

   private:
    bool enabled_ = false;
    uint32_t obfuscation_ = 0;
    std::string sequence_;
    std::vector<Association> associations_;

   public:
    bool enabled() const { return enabled_; }
    void set_enabled(bool enabled) { enabled_ = enabled; }

    uint32_t obfuscation() const { return obfuscation_; }
    void set_obfuscation(bool obfuscation) { obfuscation_ = obfuscation; }

    const std::string& sequence() const { return sequence_; }
    void set_sequence(const std::string& sequence) { sequence_ = sequence; }

    const std::vector<Association> &associations() const {
      return associations_;
    }
    void AddAssociation(const std::string& window,
                        const std::string& sequence) {
      associations_.push_back(Association(window, sequence));
    }

    bool operator==(const AutoType& other) const {
      return enabled_ == other.enabled_ &&
          obfuscation_ == other.obfuscation_ &&
          sequence_ == other.sequence_ &&
          associations_ == other.associations_;
    }
    bool operator!=(const AutoType& other) const {
      return !(*this == other);
    }
  };

  class Field final {
   private:
    std::string key_;
    protect<std::string> value_;

   public:
    Field(const std::string& key, const protect<std::string>& value) :
        key_(key), value_(value) {}
    Field(const Field& other) {
      key_ = other.key_;
      value_ = other.value_;
    }
    Field(Field&& other) {
      key_ = std::move(other.key_);
      value_ = std::move(other.value_);
    }

    const std::string& key() const { return key_; }
    const protect<std::string>& value() const { return value_; }

    Field& operator=(const Field& other) {
      key_ = other.key_;
      value_ = other.value_;
      return *this;
    }
    Field& operator=(Field&& other) {
      key_ = std::move(other.key_);
      value_ = std::move(other.value_);
      return *this;
    }

    bool operator==(const Field& other) const {
      return key_ == other.key_ &&
          value_ == other.value_;
    }
    bool operator!=(const Field& other) const {
      return !(*this == other);
    }
  };

 private:
  std::array<uint8_t, 16> uuid_;
  uint32_t icon_ = 0;
  std::weak_ptr<Icon> custom_icon_;
  protect<std::string> title_;
  protect<std::string> url_;
  std::string override_url_;
  protect<std::string> username_;
  protect<std::string> password_;
  protect<std::string> notes_;
  std::string tags_;
  std::time_t creation_time_ = 0;
  std::time_t modification_time_ = 0;
  std::time_t access_time_ = 0;
  std::time_t expiry_time_ = 0;
  std::time_t move_time_ = 0;
  bool expires_ = false;
  uint32_t usage_count_ = 0;
  std::string bg_color_;
  std::string fg_color_;
  AutoType auto_type_;
  std::vector<std::shared_ptr<Attachment>> attachments_;
  std::vector<std::shared_ptr<Entry>> history_;
  std::vector<Field> custom_fields_;

 public:
  Entry();

  const std::array<uint8_t, 16>& uuid() const { return uuid_; }
  void set_uuid(const std::array<uint8_t, 16>& uuid) { uuid_ = uuid; }

  uint32_t icon() const { return icon_; }
  void set_icon(const uint32_t& icon) { icon_ = icon; }

  std::weak_ptr<Icon> custom_icon() const { return custom_icon_; }
  void set_custom_icon(std::weak_ptr<Icon> icon) { custom_icon_ = icon; }

  const protect<std::string>& title() const { return title_; }
  void set_title(const protect<std::string>& title) { title_ = title; }

  const protect<std::string>& url() const { return url_; }
  void set_url(const protect<std::string>& url) { url_ = url; }

  const std::string& override_url() const { return override_url_; }
  void set_override_url(const std::string& url) { override_url_ = url; }

  const protect<std::string>& username() const { return username_; }
  void set_username(const protect<std::string>& username) {
    username_ = username;
  }

  const protect<std::string>& password() const { return password_; }
  void set_password(const protect<std::string>& password) {
    password_ = password;
  }

  const protect<std::string>& notes() const { return notes_; }
  void set_notes(const protect<std::string>& notes) { notes_ = notes; }

  const std::string& tags() const { return tags_; }
  void set_tags(const std::string& tags) { tags_ = tags; }

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

  bool expires() const { return expires_; }
  void set_expires(bool expires) { expires_ = expires; }

  uint32_t usage_count() const { return usage_count_; }
  void set_usage_count(uint32_t usage_count) { usage_count_ = usage_count; }

  const std::string& bg_color() const { return bg_color_; }
  void set_bg_color(const std::string& bg_color) { bg_color_ = bg_color; }

  const std::string& fg_color() const { return fg_color_; }
  void set_fg_color(const std::string& fg_color) { fg_color_ = fg_color; }

  AutoType& auto_type() { return auto_type_; }
  const std::vector<std::shared_ptr<Attachment>>& attachments() const {
    return attachments_;
  }
  const std::vector<std::shared_ptr<Entry>>& history() const {
    return history_;
  }
  const std::vector<Field>& custom_fields() const { return custom_fields_; }

  void AddAttachment(std::shared_ptr<Attachment> attachment);
  bool HasAttachment() const;
  void AddHistoryEntry(std::shared_ptr<Entry> entry);
  void AddCustomField(std::string& key, const protect<std::string>& value);

  bool HasNonDefaultAutoTypeSettings() const;
  bool IsMetaEntry() const;

  std::string ToJson() const;

  bool operator==(const Entry& other) const;
  bool operator!=(const Entry& other) const;
};

}   // namespace keepass
