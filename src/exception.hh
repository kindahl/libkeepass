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

class PasswordError final : public std::exception {
 public:
  explicit PasswordError() {}

  virtual const char* what() const throw() override {
    return "Invalid password.";
  }
};

class FormatError final : public std::exception {
 private:
  const std::string msg_;

 public:
  explicit FormatError(const std::string& msg) :
      msg_(msg) {}

  virtual const char* what() const throw() override {
    return msg_.c_str();
  }
};

/**
 * @brief Used for the same class of errors as asserts but for release builds.
 */
class InternalError : public std::exception {
 private:
  const std::string msg_;

 public:
  explicit InternalError(const std::string& msg) :
      msg_(msg) {}

  virtual const char* what() const throw() override {
    return msg_.c_str();
  }
};

class IoError : public std::exception {
 private:
  const std::string msg_;

 public:
  explicit IoError(const std::string& msg) :
      msg_(msg) {}

  virtual const char* what() const throw() override {
    return msg_.c_str();
  }
};

class FileNotFoundError final : public IoError {
 public:
  FileNotFoundError() :
      IoError("File not found.") {}
};

}   // namespace keepass
