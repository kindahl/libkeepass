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

#include <random>

#include <gtest/gtest.h>

#include "cipher.hh"

using namespace keepass;

namespace {

template <std::size_t N>
std::array<uint8_t, N> GetRandomBlock() {
  std::random_device rd;
  std::mt19937 engine(rd());

  std::uniform_int_distribution<uint8_t> uniform_dist(0, 255);

  // Fill block with random values.
  std::array<uint8_t, N> block;
  for (std::size_t i = 0; i < N; ++i)
    block[i] = uniform_dist(engine);

  return block;
}

std::array<uint8_t, 32> GetRandomKey() {
  return GetRandomBlock<32>();
}

std::array<uint8_t, 32> GetTestKey() {
  return std::array<uint8_t, 32>({
    0xbb, 0xdc, 0x2e, 0xd1, 0x42, 0x2d, 0x20, 0x1e, 
    0x7c, 0xf7, 0xd7, 0x9a, 0x22, 0x4a, 0x3a, 0x99, 
    0x48, 0x7e, 0x4f, 0x25, 0x7c, 0x59, 0x47, 0xec, 
    0x27, 0xbe, 0x50, 0x43, 0x94, 0x18, 0x00, 0xee
  });
}

void GetRandomStream(std::ostream& dst, std::size_t min_len,
                     std::size_t max_len) {
  std::random_device rd;
  std::mt19937 engine(rd());

  std::uniform_int_distribution<uint8_t> uniform_dist(0, 255);

  std::size_t len =
      std::uniform_int_distribution<uint8_t>(min_len, max_len)(engine);

  for (std::size_t i = 0; i < len; ++i) {
    uint8_t val = uniform_dist(engine);
    dst.write(reinterpret_cast<const char*>(&val), sizeof(val));
  }
}

}   // namespace

TEST(CipherTest, AesRandomBlock) {
  AesCipher cipher(GetRandomKey());

  std::array<uint8_t, 16> src_block = GetRandomBlock<16>();
  std::array<uint8_t, 16> dst_block, tst_block;
  cipher.Encrypt(src_block, dst_block);
  cipher.Decrypt(dst_block, tst_block);
  EXPECT_EQ(src_block, tst_block);
}

TEST(CipherTest, AesZeroBlock) {
  AesCipher cipher(GetRandomKey());

  std::array<uint8_t, 16> src_block = { 0 };
  std::array<uint8_t, 16> dst_block, tst_block;
  cipher.Encrypt(src_block, dst_block);
  cipher.Decrypt(dst_block, tst_block);
  EXPECT_EQ(src_block, tst_block);
}

TEST(CipherTest, AesKnownBlocks) {
  AesCipher cipher(GetTestKey());

  std::array<uint8_t, 16> src_block0 = {
    0xff, 0xce, 0x37, 0x7f, 0xe4, 0xef, 0xfc, 0xe8, 
    0xaf, 0x73, 0x7f, 0x3d, 0x6a, 0xe9, 0x90, 0xf2
  };
  std::array<uint8_t, 16> exp_block0 = {
    0xed, 0xf4, 0x43, 0x10, 0xbe, 0xda, 0xd7, 0x56, 
    0x16, 0x6c, 0xc8, 0xc4, 0xab, 0x92, 0xe9, 0xe3
  };

  std::array<uint8_t, 16> src_block1 = {
    0x2e, 0x28, 0xa8, 0x2d, 0x74, 0xc2, 0x90, 0xe7, 
    0xaa, 0x91, 0x4d, 0xb3, 0xcb, 0xdf, 0x4a, 0x44
  };
  std::array<uint8_t, 16> exp_block1 = {
    0x95, 0x09, 0x08, 0x01, 0x9b, 0xf7, 0x67, 0x21, 
    0xf9, 0x93, 0x3b, 0x17, 0x80, 0xb6, 0x40, 0x44
  };

  std::array<uint8_t, 16> src_block2 = {
    0x1d, 0xa6, 0x6b, 0xc3, 0x0a, 0x77, 0x61, 0xa0, 
    0x2c, 0x9a, 0x25, 0xa8, 0x83, 0x47, 0x0b, 0x80
  };
  std::array<uint8_t, 16> exp_block2 = {
    0x41, 0x8a, 0xb6, 0x51, 0xe5, 0x86, 0x8e, 0xd3, 
    0x9f, 0x84, 0xae, 0x28, 0xfc, 0x82, 0xd2, 0x81
  };

  std::array<uint8_t, 16> src_block3 = { 0 };
  std::array<uint8_t, 16> exp_block3 = {
    0xaf, 0x22, 0x81, 0x20, 0x79, 0x9c, 0x13, 0x46, 
    0xbf, 0x16, 0x2f, 0xbd, 0xaa, 0x7f, 0xe7, 0xf2
  };

  std::array<uint8_t, 16> src_block4 = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };
  std::array<uint8_t, 16> exp_block4 = {
    0xea, 0x4b, 0xd5, 0x56, 0x84, 0x73, 0x16, 0x2d, 
    0x50, 0xc9, 0x3c, 0x32, 0x12, 0x80, 0x58, 0xdb
  };

  std::array<uint8_t, 16> dst_block;

  cipher.Encrypt(src_block0, dst_block);
  EXPECT_EQ(dst_block, exp_block0);
  cipher.Encrypt(src_block1, dst_block);
  EXPECT_EQ(dst_block, exp_block1);
  cipher.Encrypt(src_block2, dst_block);
  EXPECT_EQ(dst_block, exp_block2);
  cipher.Encrypt(src_block3, dst_block);
  EXPECT_EQ(dst_block, exp_block3);
  cipher.Encrypt(src_block4, dst_block);
  EXPECT_EQ(dst_block, exp_block4);
}

TEST(CipherTest, TwofishRandomBlock) {
  TwofishCipher cipher(GetRandomKey());

  std::array<uint8_t, 16> src_block = GetRandomBlock<16>();
  std::array<uint8_t, 16> dst_block, tst_block;
  cipher.Encrypt(src_block, dst_block);
  cipher.Decrypt(dst_block, tst_block);
  EXPECT_EQ(src_block, tst_block);
}

TEST(CipherTest, TwofishZeroBlock) {
  TwofishCipher cipher(GetRandomKey());

  std::array<uint8_t, 16> src_block = { 0 };
  std::array<uint8_t, 16> dst_block, tst_block;
  cipher.Encrypt(src_block, dst_block);
  cipher.Decrypt(dst_block, tst_block);
  EXPECT_EQ(src_block, tst_block);
}

TEST(CipherTest, TwofishKnownBlocks) {
  TwofishCipher cipher(GetTestKey());

  std::array<uint8_t, 16> src_block0 = {
    0xff, 0xce, 0x37, 0x7f, 0xe4, 0xef, 0xfc, 0xe8,
    0xaf, 0x73, 0x7f, 0x3d, 0x6a, 0xe9, 0x90, 0xf2
  };
  std::array<uint8_t, 16> exp_block0 = {
    0xf3, 0x60, 0x9a, 0x04, 0x6d, 0x95, 0x1c, 0x4c,
    0x30, 0xb3, 0x3d, 0x9e, 0x09, 0x5c, 0x41, 0xe8
  };

  std::array<uint8_t, 16> src_block1 = {
    0x2e, 0x28, 0xa8, 0x2d, 0x74, 0xc2, 0x90, 0xe7,
    0xaa, 0x91, 0x4d, 0xb3, 0xcb, 0xdf, 0x4a, 0x44
  };
  std::array<uint8_t, 16> exp_block1 = {
    0xcf, 0xac, 0x7a, 0xd5, 0x8b, 0x1e, 0x84, 0x0e,
    0x47, 0xac, 0xa6, 0xf5, 0xe3, 0x6e, 0xa3, 0x13
  };

  std::array<uint8_t, 16> src_block2 = {
    0x1d, 0xa6, 0x6b, 0xc3, 0x0a, 0x77, 0x61, 0xa0,
    0x2c, 0x9a, 0x25, 0xa8, 0x83, 0x47, 0x0b, 0x80
  };
  std::array<uint8_t, 16> exp_block2 = {
    0x1f, 0xd8, 0x14, 0x7c, 0x7e, 0xf3, 0xb3, 0xf7,
    0x68, 0x2d, 0x90, 0x8b, 0xb1, 0x23, 0x4b, 0xf3
  };

  std::array<uint8_t, 16> src_block3 = { 0 };
  std::array<uint8_t, 16> exp_block3 = {
    0xf8, 0x03, 0xa7, 0xfd, 0x87, 0x1e, 0xdc, 0x35,
    0x10, 0x35, 0x8c, 0xb2, 0x04, 0x94, 0x75, 0x26
  };

  std::array<uint8_t, 16> src_block4 = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };
  std::array<uint8_t, 16> exp_block4 = {
    0x26, 0x14, 0xe6, 0xbf, 0x9a, 0x78, 0x9e, 0x4b,
    0xbf, 0xf8, 0xd5, 0x72, 0x30, 0xa1, 0xd7, 0x8e
  };

  std::array<uint8_t, 16> dst_block;

  cipher.Encrypt(src_block0, dst_block);
  EXPECT_EQ(dst_block, exp_block0);
  cipher.Encrypt(src_block1, dst_block);
  EXPECT_EQ(dst_block, exp_block1);
  cipher.Encrypt(src_block2, dst_block);
  EXPECT_EQ(dst_block, exp_block2);
  cipher.Encrypt(src_block3, dst_block);
  EXPECT_EQ(dst_block, exp_block3);
  cipher.Encrypt(src_block4, dst_block);
  EXPECT_EQ(dst_block, exp_block4);
}

TEST(CipherTest, Ecb) {
  AesCipher cipher(GetRandomKey());

  std::array<uint8_t, 32> src_blocks = GetRandomBlock<32>();
  std::array<uint8_t, 32> dst_blocks, tst_blocks;
  EXPECT_NO_THROW({
    dst_blocks = encrypt_ecb(src_blocks, cipher);
  });
  EXPECT_NO_THROW({
    tst_blocks = decrypt_ecb(dst_blocks, cipher);
  });
  EXPECT_EQ(src_blocks, tst_blocks);
}

TEST(CipherTest, CbcWithFullPadding) {
  AesCipher cipher(GetRandomKey());

  std::stringstream src, dst, tst;
  GetRandomStream(src, 128, 128);
  EXPECT_EQ(src.str().size(), 128);

  EXPECT_NO_THROW(encrypt_cbc(src, dst, cipher));
  EXPECT_EQ(dst.str().size() % 16, 0);

  src.seekg(0, std::ios::beg);
  src.clear();
  dst.seekg(0, std::ios::beg);
  dst.clear();

  EXPECT_NO_THROW(decrypt_cbc(dst, tst, cipher));
  EXPECT_EQ(src.str(), tst.str());
}

TEST(CipherTest, CbcWithRandomPadding) {
  AesCipher cipher(GetRandomKey());

  std::stringstream src, dst, tst;
  GetRandomStream(src, 129, 143);
  EXPECT_NE(src.str().size() % 16, 0);

  EXPECT_NO_THROW(encrypt_cbc(src, dst, cipher));
  EXPECT_EQ(dst.str().size() % 16, 0);

  src.seekg(0, std::ios::beg);
  src.clear();
  dst.seekg(0, std::ios::beg);
  dst.clear();

  EXPECT_NO_THROW(decrypt_cbc(dst, tst, cipher));
  EXPECT_EQ(src.str(), tst.str());
}
