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

namespace keepass {

/**
 * @brief Template class for keeping track of when a variable is modified.
 */
template <typename T>
class temporal {
 private:
  T value_;
  std::time_t time_ = 0;

 public:
  temporal() = default;
  temporal(const T& value, std::time_t time) :
      value_(value), time_(time) {}
  temporal(const temporal<T>& other) {
    value_ = other.value_;
    time_ = other.time_;
  }
  temporal(temporal<T>&& other) {
    value_ = std::move(other.value_);
    time_ = std::move(other.time_);
  }

  const T& value() const { return value_; }

  std::time_t time() const { return time_; }
  void set_time(std::time_t time) { time_ = time; }

  void Set(const T& val) {
    value_ = val;
    time_ = std::time(nullptr);
  }

  temporal<T>& operator=(const T& value) {
    value_ = value;
    time_ = std::time(nullptr);
    return *this;
  }
  temporal<T>& operator=(const temporal<T>& other) {
    value_ = other.value_;
    time_ = other.time_;
    return *this;
  }
  temporal<T>& operator=(temporal<T>&& other) {
    value_ = std::move(other.value_);
    time_ = std::move(other.time_);
    return *this;
  }
  operator const T&() const {
    return value_;
  }
  const T* operator->() const {
    return &value_;
  }
  const T& operator*() const {
    return value_;
  }
};

}   // namespace keepass
