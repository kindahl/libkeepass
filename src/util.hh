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
#include <array>
#include <algorithm>
#include <cassert>
#include <ctime>
#include <istream>
#include <string>

namespace keepass {

template <typename T>
inline T clamp(T min, T max, T val) {
  return std::max<T>(min, std::min<T>(max, val));
}

template <typename T>
inline T consume(std::istream& src) {
  T val;
  src.read(reinterpret_cast<char *>(&val), sizeof(T));
  if (!src.good())
    throw std::runtime_error("trying to consume past data limit.");

  return val;
}

template <>
std::string consume<std::string>(std::istream& src);

template <>
std::vector<char> consume<std::vector<char>>(std::istream& src);

template<typename T>
void conserve(std::ostream& dst, T val) {
  dst.write(reinterpret_cast<const char*>(&val), sizeof(T));
}

template <std::size_t N>
class array_iostreambuf :
    public std::basic_streambuf<char, std::char_traits<char>> {
 private:
  std::array<uint8_t, N>& buffer_;

 protected:
  virtual std::streampos seekoff(std::streamoff off,
                                 std::ios_base::seekdir way,
                                 std::ios_base::openmode which) override {
    if (which == 0)
      return std::streampos(std::streamoff(-1));

    off = clamp<std::streamoff>(0, buffer_.size(), off);

    std::streamoff lin_off = 0;
    switch (way) {
      case std::ios_base::beg:
        lin_off = clamp<std::streamoff>(0, buffer_.size(), off);
        break;
      case std::ios_base::cur:
        lin_off = clamp<std::streamoff>(0, buffer_.size(), (gptr() - eback()) + off);
        break;
      case std::ios_base::end:
        lin_off = clamp<std::streamoff>(0, buffer_.size(), buffer_.size() - off);
        break;
      default:
        assert(false);
        break;
    };

    if (which & std::ios_base::in) {
      char* buffer_ptr = reinterpret_cast<char*>(buffer_.data());
      setg(buffer_ptr, buffer_ptr + lin_off, buffer_ptr + buffer_.size());
    }

    return lin_off;
  }

  virtual std::streampos seekpos(std::streampos sp,
                                 std::ios_base::openmode which) override {
    if (which == 0 || sp < 0 || sp >= buffer_.size())
      return std::streampos(std::streamoff(-1));

    if (which & std::ios_base::in) {
      char* buffer_ptr = reinterpret_cast<char*>(buffer_.data());
      setg(buffer_ptr, buffer_ptr + sp, buffer_ptr + buffer_.size());
    }

    return sp;
  }

 public:
  array_iostreambuf(std::array<uint8_t, N>& buffer) : buffer_(buffer) {
    char* buffer_ptr = reinterpret_cast<char*>(buffer.data());
    setg(buffer_ptr, buffer_ptr, buffer_ptr + buffer.size());
    setp(buffer_ptr, buffer_ptr + buffer.size());
  }
};

/**
 * Compares the elements in two vectors for equality. This function is designed
 * for vectors containing pointer types and will dereference each element
 * before comparison.
 * @param [in] v0 First vector.
 * @param [in] v1 Second vector.
 * @return true if all (dereferenced) elements of @a v1 and @a v2 are equal.
 *         If not, the function returns false.
 */
template <typename T>
inline bool indirect_equal(const std::vector<T>& v0,
                           const std::vector<T>& v1) {
  return std::equal(v0.begin(), v0.end(), v1.begin(),
      [](const T& v0, const T& v1) {
        return *v0 == *v1;
      });
}

std::string time_to_str(const std::time_t &time);

}   // namespace keepass
