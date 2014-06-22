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

namespace keepass {

/**
 * @brief Tempalte class which encrypts the content bytes in memory.
 *
 * FIXME: Implement protection.
 */
template <typename T>
class protect {
 private:
  T value_;
  bool protected_ = false;

 public:
  protect() = default;
  protect(const T& val, bool prot) :
      value_(val), protected_(prot) {}
  protect(const protect<T>& other) {
    value_ = other.value_;
    protected_ = other.protected_;
  }
  protect(protect<T>&& other) {
    value_ = std::move(other.value_);
    protected_ = std::move(other.protected_);
  }

  bool is_protected() const { return protected_; }
  void set_protected(bool prot) { protected_ = prot; }

  const T& value() const { return value_; }
  void set_value(const T& val) { value_ = val; }

  protect<T>& operator=(const protect<T>& other) {
    value_ = other.value_;
    protected_ = other.protected_;
    return *this;
  }
  protect<T>& operator=(protect<T>&& other) {
    value_ = std::move(other.value_);
    protected_ = std::move(other.protected_);
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
  bool operator==(const protect<T>& other) const {
    return value_ == other.value_ &&
        protected_ == other.protected_;
  }
  bool operator!=(const protect<T>& other) const {
    return !(*this == other);
  }
};

}   // namespace keepass
