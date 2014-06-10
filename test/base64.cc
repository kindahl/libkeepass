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

#include "base64.hh"

using namespace keepass;

TEST(Base64Test, Empty) {
  EXPECT_EQ(base64_encode(""), "");
  EXPECT_EQ(base64_decode(""), "");
}

TEST(Base64Test, SingleCharacter) {
  std::string txt = "a";
  std::string b64 = "YQ==";
  EXPECT_EQ(base64_encode(txt), b64);
  EXPECT_EQ(base64_decode(b64), txt);
}

TEST(Base64Test, TwoCharacters) {
  std::string txt = "ab";
  std::string b64 = "YWI=";
  EXPECT_EQ(base64_encode(txt), b64);
  EXPECT_EQ(base64_decode(b64), txt);
}

TEST(Base64Test, NoPadding) {
  std::string txt = "Lorem ipsum dolor sit amet, consectetur adipi";
  std::string b64 =
      "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBp";
  EXPECT_EQ(base64_encode(txt), b64);
  EXPECT_EQ(base64_decode(b64), txt);
}

TEST(Base64Test, SinglePadding) {
  std::string txt = "Lorem ipsum dolor sit amet, consectetur adip";
  std::string b64 =
      "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXA=";
  EXPECT_EQ(base64_encode(txt), b64);
  EXPECT_EQ(base64_decode(b64), txt);
}

TEST(Base64Test, DoublePadding) {
  std::string txt = "Lorem ipsum dolor sit amet, consectetur adipis";
  std::string b64 =
      "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpcw==";
  EXPECT_EQ(base64_encode(txt), b64);
  EXPECT_EQ(base64_decode(b64), txt);
}

TEST(Base64Test, Random) {
  std::string b64 = "BVCMCiBeLkKGz72bzLDGeQ==";
  EXPECT_EQ(base64_encode(base64_decode(b64)), b64);
}
