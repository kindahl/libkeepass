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

#include <set>

#include <gtest/gtest.h>

#include "util.hh"

using namespace keepass;

TEST(UtilTest, GenerateUuid) {
  // Generate 100 UUIDs and make sure that none of them are the same.
  std::set<std::array<uint8_t, 16>> generated;
  for (std::size_t i = 0; i < 100; ++i) {
    std::array<uint8_t, 16> uuid = generate_uuid();
    EXPECT_EQ(generated.count(uuid), 0);
    generated.insert(uuid);
  }
}
