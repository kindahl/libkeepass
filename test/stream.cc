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

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "stream.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return "./test/data/" + name;
}

std::string GetTmpPath(const std::string& name) {
  return "./test/tmp/" + name;
}

bool FilesEqual(const std::string& path0, const std::string& path1) {
  std::ifstream file0(path0, std::ios::in | std::ios::binary);
  std::ifstream file1(path1, std::ios::in | std::ios::binary);
  if (!file0.is_open() || !file1.is_open())
    return false;

  std::vector<char> data0, data1;
  std::copy(std::istreambuf_iterator<char>(file0), 
            std::istreambuf_iterator<char>(), 
            std::back_inserter(data0));
  std::copy(std::istreambuf_iterator<char>(file1), 
            std::istreambuf_iterator<char>(), 
            std::back_inserter(data1));

  return data0 == data1;
}

std::string GetFileAsText(const std::string& path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  return std::string(std::istreambuf_iterator<char>(file),
                     std::istreambuf_iterator<char>());
}

}   // namespace

TEST(StreamTest, ReadEmptyHashedStream) {
  std::ifstream file(GetTestPath("hashed_stream-0"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 0);
}

TEST(StreamTest, Read26BytesHashedStream) {
  std::ifstream file(GetTestPath("hashed_stream-26"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 26);
}

TEST(StreamTest, Read128BytesHashedStream) {
  std::ifstream file(GetTestPath("hashed_stream-128"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 128);
}

TEST(StreamTest, Read130BytesHashedStream) {
  std::ifstream file(GetTestPath("hashed_stream-130"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 130);
}

TEST(StreamTest, Read260BytesHashedStream) {
  std::ifstream file(GetTestPath("hashed_stream-260"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 260);
}

TEST(StreamTest, ReadBadHashedStream) {
  std::ifstream file(GetTestPath("hashed_stream-260-bad"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  EXPECT_THROW({
    std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                  std::istreambuf_iterator<char>());
  }, std::runtime_error);
}

TEST(StreamTest, WriteEmptyHashedStream) {
  const std::string dst_path = GetTmpPath("hashed_stream-0");
  const std::string tst_path = GetTestPath("hashed_stream-0");

  std::ofstream file(dst_path, std::ios::out | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_ostreambuf streambuf(file, 128);
  std::ostream stream(&streambuf);
  stream.flush();
  EXPECT_EQ(stream.good(), true);
  file.close();

  EXPECT_EQ(FilesEqual(tst_path, dst_path), true);
  std::remove(dst_path.c_str());
}

TEST(StreamTest, Write26BytesHashedStream) {
  const std::string dst_path = GetTmpPath("hashed_stream-26");
  const std::string tst_path = GetTestPath("hashed_stream-26");

  std::ofstream file(dst_path, std::ios::out | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_ostreambuf streambuf(file, 128);
  std::ostream stream(&streambuf);
  stream << "abcdefghijklmnopqrstuvwxyz";
  stream.flush();
  EXPECT_EQ(stream.good(), true);
  file.close();

  EXPECT_EQ(FilesEqual(tst_path, dst_path), true);
  std::remove(dst_path.c_str());
}

TEST(StreamTest, Write128BytesHashedStream) {
  const std::string dst_path = GetTmpPath("hashed_stream-128");
  const std::string tst_path = GetTestPath("hashed_stream-128");

  std::ofstream file(dst_path, std::ios::out | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_ostreambuf streambuf(file, 128);
  std::ostream stream(&streambuf);
  stream << "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwx";
  stream.flush();
  EXPECT_EQ(stream.good(), true);
  file.close();

  EXPECT_EQ(FilesEqual(tst_path, dst_path), true);
  std::remove(dst_path.c_str());
}

TEST(StreamTest, Write130BytesHashedStream) {
  const std::string dst_path = GetTmpPath("hashed_stream-130");
  const std::string tst_path = GetTestPath("hashed_stream-130");

  std::ofstream file(dst_path, std::ios::out | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_ostreambuf streambuf(file, 128);
  std::ostream stream(&streambuf);
  stream << "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz";
  stream.flush();
  EXPECT_EQ(stream.good(), true);
  file.close();

  EXPECT_EQ(FilesEqual(tst_path, dst_path), true);
  std::remove(dst_path.c_str());
}

TEST(StreamTest, Write260BytesHashedStream) {
  const std::string dst_path = GetTmpPath("hashed_stream-260");
  const std::string tst_path = GetTestPath("hashed_stream-260");

  std::ofstream file(dst_path, std::ios::out | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  hashed_ostreambuf streambuf(file, 128);
  std::ostream stream(&streambuf);
  stream << "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz" <<
      "abcdefghijklmnopqrstuvwxyz" << "abcdefghijklmnopqrstuvwxyz";
  stream.flush();
  EXPECT_EQ(stream.good(), true);
  file.close();

  EXPECT_EQ(FilesEqual(tst_path, dst_path), true);
  std::remove(dst_path.c_str());
}

TEST(StreamTest, ReadEmptyGzipStream) {
  std::ifstream file(GetTestPath("gzip_stream-0.gzip"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  gzip_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 0);
}

TEST(StreamTest, Read127BytesGzipStream) {
  std::ifstream file(GetTestPath("gzip_stream-127.gzip"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  gzip_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 127);
  EXPECT_EQ(str, GetFileAsText(GetTestPath("gzip_stream-127")));
}

TEST(StreamTest, Read16384BytesGzipStream) {
  std::ifstream file(GetTestPath("gzip_stream-16384.gzip"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  gzip_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 16384);
  EXPECT_EQ(str, GetFileAsText(GetTestPath("gzip_stream-16384")));
}

TEST(StreamTest, Read16511BytesGzipStream) {
  std::ifstream file(GetTestPath("gzip_stream-16511.gzip"),
                     std::ios::in | std::ios::binary);
  EXPECT_EQ(file.is_open(), true);

  gzip_istreambuf streambuf(file);
  std::istream stream(&streambuf);

  std::string str = std::string(std::istreambuf_iterator<char>(stream),
                                std::istreambuf_iterator<char>());
  EXPECT_EQ(stream.good(), true);
  EXPECT_EQ(str.size(), 16511);
  EXPECT_EQ(str, GetFileAsText(GetTestPath("gzip_stream-16511")));
}
