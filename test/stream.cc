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

#include "exception.hh"
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
  }, IoError);
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

TEST(StreamTest, WriteEmptyGzipStream) {
  const std::string src_path = GetTestPath("gzip_stream-0");
  const std::string arc_path = GetTmpPath("gzip_stream-0.gzip");
  const std::string tst_path = GetTmpPath("gzip_stream-0");

  // Compress the file.
  {
    std::ifstream src(src_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(src.is_open(), true);

    std::ofstream arc(arc_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    gzip_ostreambuf ostreambuf(arc);
    std::ostream ostream(&ostreambuf);
    std::copy(std::istreambuf_iterator<char>(src),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(ostream));
    ostream.flush();
    EXPECT_EQ(ostream.good(), true);
    arc.close();
    src.close();
  }

  // Decompress the file.
  {
    std::ifstream arc(arc_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    std::ofstream tst(tst_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(tst.is_open(), true);

    gzip_istreambuf istreambuf(arc);
    std::istream istream(&istreambuf);
    std::copy(std::istreambuf_iterator<char>(istream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(tst));
    tst.flush();
    EXPECT_EQ(istream.good(), true);
    tst.close();
    arc.close();
  }

  EXPECT_EQ(FilesEqual(src_path, tst_path), true);
  std::remove(arc_path.c_str());
  std::remove(tst_path.c_str());
}

TEST(StreamTest, Write127BytesGzipStream) {
  const std::string src_path = GetTestPath("gzip_stream-127");
  const std::string arc_path = GetTmpPath("gzip_stream-127.gzip");
  const std::string tst_path = GetTmpPath("gzip_stream-127");

  // Compress the file.
  {
    std::ifstream src(src_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(src.is_open(), true);

    std::ofstream arc(arc_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    gzip_ostreambuf ostreambuf(arc);
    std::ostream ostream(&ostreambuf);
    std::copy(std::istreambuf_iterator<char>(src),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(ostream));
    ostream.flush();
    EXPECT_EQ(ostream.good(), true);
    arc.close();
    src.close();
  }

  // Decompress the file.
  {
    std::ifstream arc(arc_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    std::ofstream tst(tst_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(tst.is_open(), true);

    gzip_istreambuf istreambuf(arc);
    std::istream istream(&istreambuf);
    std::copy(std::istreambuf_iterator<char>(istream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(tst));
    tst.flush();
    EXPECT_EQ(istream.good(), true);
    tst.close();
    arc.close();
  }

  EXPECT_EQ(FilesEqual(src_path, tst_path), true);
  std::remove(arc_path.c_str());
  std::remove(tst_path.c_str());
}

TEST(StreamTest, Write16384BytesGzipStream) {
  const std::string src_path = GetTestPath("gzip_stream-16384");
  const std::string arc_path = GetTmpPath("gzip_stream-16384.gzip");
  const std::string tst_path = GetTmpPath("gzip_stream-16384");

  // Compress the file.
  {
    std::ifstream src(src_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(src.is_open(), true);

    std::ofstream arc(arc_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    gzip_ostreambuf ostreambuf(arc);
    std::ostream ostream(&ostreambuf);
    std::copy(std::istreambuf_iterator<char>(src),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(ostream));
    ostream.flush();
    EXPECT_EQ(ostream.good(), true);
    arc.close();
    src.close();
  }

  // Decompress the file.
  {
    std::ifstream arc(arc_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    std::ofstream tst(tst_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(tst.is_open(), true);

    gzip_istreambuf istreambuf(arc);
    std::istream istream(&istreambuf);
    std::copy(std::istreambuf_iterator<char>(istream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(tst));
    tst.flush();
    EXPECT_EQ(istream.good(), true);
    tst.close();
    arc.close();
  }

  EXPECT_EQ(FilesEqual(src_path, tst_path), true);
  std::remove(arc_path.c_str());
  std::remove(tst_path.c_str());
}

TEST(StreamTest, Write16511BytesGzipStream) {
  const std::string src_path = GetTestPath("gzip_stream-16511");
  const std::string arc_path = GetTmpPath("gzip_stream-16511.gzip");
  const std::string tst_path = GetTmpPath("gzip_stream-16511");

  // Compress the file.
  {
    std::ifstream src(src_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(src.is_open(), true);

    std::ofstream arc(arc_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    gzip_ostreambuf ostreambuf(arc);
    std::ostream ostream(&ostreambuf);
    std::copy(std::istreambuf_iterator<char>(src),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(ostream));
    ostream.flush();
    EXPECT_EQ(ostream.good(), true);
    arc.close();
    src.close();
  }

  // Decompress the file.
  {
    std::ifstream arc(arc_path, std::ios::in | std::ios::binary);
    EXPECT_EQ(arc.is_open(), true);

    std::ofstream tst(tst_path, std::ios::out | std::ios::binary);
    EXPECT_EQ(tst.is_open(), true);

    gzip_istreambuf istreambuf(arc);
    std::istream istream(&istreambuf);
    std::copy(std::istreambuf_iterator<char>(istream),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(tst));
    tst.flush();
    EXPECT_EQ(istream.good(), true);
    tst.close();
    arc.close();
  }

  EXPECT_EQ(FilesEqual(src_path, tst_path), true);
  std::remove(arc_path.c_str());
  std::remove(tst_path.c_str());
}
