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

#include <gtest/gtest.h>

#include "iterator.hh"

using namespace keepass;

TEST(IteratorTest, CheckBounds) {
  std::string src = "abcdef";
  std::string dst;
  EXPECT_THROW({
    std::copy(src.begin(), src.end(), bounds_checked(dst));
  }, std::out_of_range);
  EXPECT_EQ(dst, "");

  dst.clear();
  dst.resize(5);
  EXPECT_THROW({
    std::copy(src.begin(), src.end(), bounds_checked(dst));
  }, std::out_of_range);
  EXPECT_EQ(dst, "abcde");

  dst.clear();
  dst.resize(6);
  EXPECT_NO_THROW({
    std::copy(src.begin(), src.end(), bounds_checked(dst));
  });
  EXPECT_EQ(dst, "abcdef");

  dst.clear();
  dst.resize(7);
  EXPECT_NO_THROW({
    std::copy(src.begin(), src.end(), bounds_checked(dst));
  });

  dst.clear();
  dst.resize(16);
  EXPECT_NO_THROW({
    std::copy(src.begin(), src.end(), bounds_checked(dst));
  });
}
