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
#include <algorithm>
#include <memory>
#include <istream>
#include <ostream>

#include <zlib.h>

namespace keepass {

class hashed_basic_streambuf {
 protected:
  struct BlockHeader {
    uint32_t block_index;
    std::array<uint8_t, 32> block_hash;
    uint32_t block_size = 0;
  };

  uint32_t block_index_ = 0;
  std::vector<char> block_;

  std::array<uint8_t, 32> GetBlockHash() const;

 public:
  virtual ~hashed_basic_streambuf() = default;
};

class hashed_istreambuf final :
    private hashed_basic_streambuf,
    public std::basic_streambuf<char, std::char_traits<char>> {
 private:
  std::istream& src_;

public:
  hashed_istreambuf(std::istream& src)
    : src_(src) {}

  virtual int underflow() override;
};

class hashed_ostreambuf final :
    private hashed_basic_streambuf,
    public std::basic_streambuf<char, std::char_traits<char>> {
 private:
  static constexpr uint32_t kDefaultBlockSize = 1024 * 1024;

  std::ostream& dst_;
  const uint32_t block_size_;

  bool FlushBlock();

public:
  hashed_ostreambuf(std::ostream& dst)
    : dst_(dst), block_size_(kDefaultBlockSize) {}
  hashed_ostreambuf(std::ostream& dst, uint32_t block_size)
    : dst_(dst), block_size_(block_size) {}

  virtual int overflow(int c) override;
  virtual int sync() override;
};

class gzip_istreambuf final :
    public std::basic_streambuf<char, std::char_traits<char>> {
 private:
  static const std::size_t kBufferSize = 16384;

  std::istream& src_;
  z_stream z_stream_;

  /** Input buffer for feeding the decompressor. */
  std::array<char, kBufferSize> input_ = { { 0 } };
  /** Output buffer for the decompressor to write to. */
  std::array<char, kBufferSize> output_ = { { 0 } };

public:
  gzip_istreambuf(std::istream& src);
  ~gzip_istreambuf();

  virtual int underflow() override;
};

}   // namespace keepass
