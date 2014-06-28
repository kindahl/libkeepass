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
#include "icon.hh"
#include "temporal.hh"

namespace keepass {

class Group;

class Metadata final {
 public:
  class MemoryProtection final {
   private:
    bool title_ = false;
    bool username_ = false;
    bool password_ = true;
    bool url_ = false;
    bool notes_ = false;

   public:
    bool title() const { return title_; }
    void set_title(bool title) { title_ = title; }

    bool username() const { return username_; }
    void set_username(bool username) { username_ = username; }

    bool password() const { return password_; }
    void set_password(bool password) { password_ = password; }

    bool url() const { return url_; }
    void set_url(bool url) { url_ = url; }

    bool notes() const { return notes_; }
    void set_notes(bool notes) { notes_ = notes; }
  };

  class Field final {
   private:
    std::string key_;
    std::string value_;

   public:
    Field(const std::string& key, const std::string& value) :
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
    const std::string& value() const { return value_; }

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
  };

 private:
  std::string generator_;
  temporal<std::string> database_name_;
  temporal<std::string> database_desc_;
  temporal<std::string> default_username_;
  uint32_t maintenance_hist_days_ = 365;
  std::string database_color_;
  std::time_t master_key_changed_ = 0;
  int64_t master_key_change_rec_ = -1;
  int64_t master_key_change_force_ = -1;
  MemoryProtection memory_protection_;
  std::shared_ptr<Group> recycle_bin_;
  std::time_t recycle_bin_changed_;
  std::shared_ptr<Group> entry_templates_;
  std::time_t entry_templates_changed_;
  int32_t history_max_items_ = -1;
  int64_t history_max_size_ = -1;
  std::weak_ptr<Group> last_selected_group_;
  std::weak_ptr<Group> last_visible_group_;

  std::vector<std::shared_ptr<Binary>> binaries_;
  std::vector<std::shared_ptr<Icon>> icons_;
  std::vector<Field> fields_;

 public:
  const std::string& generator() const { return generator_; }
  void set_generator(const std::string& generator) { generator_ = generator; }

  const temporal<std::string>& database_name() const { return database_name_; }
  void set_database_name(const temporal<std::string>& name) {
    database_name_ = name;
  }

  const temporal<std::string>& database_desc() const { return database_desc_; }
  void set_database_desc(const temporal<std::string>& desc) {
    database_desc_ = desc;
  }

  const temporal<std::string>& default_username() const {
    return default_username_;
  }
  void set_default_username(const temporal<std::string>& username) {
    default_username_ = username;
  }

  uint32_t maintenance_hist_days() const { return maintenance_hist_days_; }
  void set_maintenance_hist_days(uint32_t days) {
    maintenance_hist_days_ = days;
  }

  const std::string& database_color() const { return database_color_; }
  void set_database_color(const std::string& color) {
    database_color_ = color;
  }

  std::time_t master_key_changed() const { return master_key_changed_; }
  void set_master_key_changed(std::time_t time) {
    master_key_changed_ = time;
  }

  int64_t master_key_change_rec() const { return master_key_change_rec_; }
  void set_master_key_change_rec(int64_t rec) { master_key_change_rec_ = rec; }

  int64_t master_key_change_force() const { return master_key_change_force_; }
  void set_master_key_change_force(int64_t force) {
    master_key_change_force_ = force;
  }

  MemoryProtection& memory_protection() { return memory_protection_; }

  std::shared_ptr<Group> recycle_bin() const { return recycle_bin_; }
  void set_recycle_bin(std::shared_ptr<Group> bin) { recycle_bin_ = bin; }

  std::time_t recycle_bin_changed() const { return recycle_bin_changed_; }
  void set_recycle_bin_changed(std::time_t time) {
    recycle_bin_changed_ = time;
  }

  std::shared_ptr<Group> entry_templates() const { return entry_templates_; }
  void set_entry_templates(std::shared_ptr<Group> entry_templates) {
    entry_templates_ = entry_templates;
  }

  std::time_t entry_templates_changed() const {
    return entry_templates_changed_;
  }
  void set_entry_templates_changed(std::time_t time) {
    entry_templates_changed_ = time;
  }

  int32_t history_max_items() const { return history_max_items_; }
  void set_history_max_items(int32_t max) { history_max_items_ = max; }

  int64_t history_max_size() const { return history_max_size_; }
  void set_history_max_size(int64_t max) { history_max_size_ = max; }

  std::weak_ptr<Group> last_selected_group() const {
    return last_selected_group_;
  }
  void set_last_selected_group(std::weak_ptr<Group> group) {
    last_selected_group_ = group;
  }

  std::weak_ptr<Group> last_visible_group() const {
    return last_visible_group_;
  }
  void set_last_visible_group(std::weak_ptr<Group> group) {
    last_visible_group_ = group;
  }

  const std::vector<std::shared_ptr<Binary>>& binaries() const {
    return binaries_;
  }
  const std::vector<std::shared_ptr<Icon>>& icons() const {
    return icons_;
  }
  const std::vector<Field>& fields() const { return fields_; }

  void AddBinary(std::shared_ptr<Binary> binary);
  void AddIcon(std::shared_ptr<Icon> icon);
  void AddField(const std::string& key, const std::string& value);
};

}   // namespace keepass
