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

#include "cipher.hh"

#include <algorithm>
#include <cassert>
#include <cstring>

#include "exception.hh"
#include "stream.hh"
#include "util.hh"

namespace {

template <std::size_t N>
using BlockOperation = std::function<std::size_t(const std::array<uint8_t, N>&,
                                                 std::array<uint8_t, N>&,
                                                 std::size_t,
                                                 bool)>;

template <std::size_t N>
void block_transform(
    std::istream& src, std::ostream& dst,
    BlockOperation<N> op) {
  std::array<uint8_t, N> src_block, dst_block;

  std::streampos pos = src.tellg();
  src.seekg(0, std::ios::end);
  std::streampos end = src.tellg();
  src.seekg(pos, std::ios::beg);

  std::streamsize remaining = end - pos;

  while (src.good()) {
    src.read(reinterpret_cast<char *>(src_block.data()), src_block.size());
    if (src.eof() && src.gcount() == 0)
      break;

    std::streamsize read_bytes = src.gcount();
    remaining -= read_bytes;

    std::size_t dst_bytes = op(
        src_block, dst_block, read_bytes, remaining == 0);

    dst.write(reinterpret_cast<const char*>(dst_block.data()), dst_bytes);
  }
}

}

namespace keepass {

void encrypt_ecb(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len,
                                    bool) -> std::size_t {
    if (src_len != 16) {
      assert(false);
      throw InternalError("ECB can only encrypt an even number of blocks.");
    }

    cipher.Encrypt(src, dst);
    return 16;
  });
}

void decrypt_ecb(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len,
                                    bool) -> std::size_t {
    if (src_len != 16) {
      assert(false);
      throw InternalError("ECB can only decrypt an even number of blocks.");
    }

    cipher.Decrypt(src, dst);
    return 16;
  });
}

std::array<uint8_t, 32> encrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher) {
  std::array<uint8_t, 32> arr = src;
  std::array<uint8_t, 32> dst = src;

  array_iostreambuf<32> src_buf(arr);
  array_iostreambuf<32> dst_buf(dst);

  std::istream src_stream(&src_buf);
  std::ostream dst_stream(&dst_buf);

  encrypt_ecb(src_stream, dst_stream, cipher);
  return dst;
}

std::array<uint8_t, 32> decrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher) {
  std::array<uint8_t, 32> arr = src;
  std::array<uint8_t, 32> dst = src;

  array_iostreambuf<32> src_buf(arr);
  array_iostreambuf<32> dst_buf(dst);

  std::istream src_stream(&src_buf);
  std::ostream dst_stream(&dst_buf);

  decrypt_ecb(src_stream, dst_stream, cipher);
  return dst;
}

void encrypt_cbc(std::istream& src, std::ostream& dst,
                 const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  uint32_t pad_len = 0;
  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len,
                                    bool) -> std::size_t {
    std::array<uint8_t, 16> src_xor_iv;
    std::transform(src.begin(), src.end(),
                   prv.begin(), src_xor_iv.begin(),
                   std::bit_xor<uint8_t>());

    if (src_len != 16) {
      // Handle PKCS #7 padding for the last block.
      assert(src_len <= 16);
      pad_len = 16 - src_len;
      assert(pad_len > 0 && pad_len <= 16);

      for (std::size_t i = 16 - pad_len; i < 16; i++) {
        src_xor_iv[i] = static_cast<uint8_t>(pad_len) ^ prv[i];
      }
    }

    cipher.Encrypt(src_xor_iv, dst);
    prv = dst;

    return 16;
  });

  // We must always apply padding.
  if (pad_len == 0) {
    std::array<uint8_t, 16> src_block, dst_block;
    std::array<uint8_t, 16> src_block_xor_iv;

    std::fill(src_block.begin(), src_block.end(), 16);
    std::transform(src_block.begin(), src_block.end(),
                   prv.begin(), src_block_xor_iv.begin(),
                   std::bit_xor<uint8_t>());

    cipher.Encrypt(src_block_xor_iv, dst_block);
    dst.write(reinterpret_cast<const char*>(dst_block.data()),
              dst_block.size());
  }
}

void decrypt_cbc(std::istream& src, std::ostream& dst, const Cipher<16>& cipher) {
  std::array<uint8_t, 16> prv = cipher.InitializationVector();

  block_transform<16>(src, dst, [&](const std::array<uint8_t, 16>& src,
                                    std::array<uint8_t, 16>& dst,
                                    std::size_t src_len,
                                    bool last) -> std::size_t {
    if (src_len != 16)
      throw IoError("Decryption error.");

    cipher.Decrypt(src, dst);

    std::transform(dst.begin(), dst.end(),
                   prv.begin(), dst.begin(),
                   std::bit_xor<uint8_t>());

    if (last) {
      // Handle PKCS #7 padding for the last block.
      uint32_t pad_len = dst[15];
      if (pad_len > 16)
        throw IoError("Decryption error.");

      for (std::size_t i = 16 - pad_len; i < 16; ++i) {
        if (dst[i] != pad_len)
          throw IoError("Decryption error.");
      }

      return 16 - pad_len;
    }

    prv = src;
    return 16;
  });
}

AesCipher::AesCipher(const std::array<uint8_t, 32>& key,
                     const std::array<uint8_t, 16>& init_vec) :
    init_vec_(init_vec) {
  if (AES_set_decrypt_key(key.data(), 256, &key_dec_) != 0) {
    assert(false);
  }
  if (AES_set_encrypt_key(key.data(), 256, &key_enc_) != 0) {
    assert(false);
  }
}

void AesCipher::Decrypt(const std::array<uint8_t, 16>& src,
                        std::array<uint8_t, 16>& dst) const {
  AES_decrypt(src.data(), dst.data(), &key_dec_);
}

void AesCipher::Encrypt(const std::array<uint8_t, 16>& src,
                        std::array<uint8_t, 16>& dst) const {
  AES_encrypt(src.data(), dst.data(), &key_enc_);
}

uint32_t TwofishCipher::ReedSolomonEncode(uint32_t k0, uint32_t k1) const {
  static const uint32_t kRsGfFdbk = 0x14d;

  uint32_t r = 0;
  for (std::size_t i = 0 ; i < 2; ++i) {
    // Merge in 32 more key bits.
    r ^= i ? k0 : k1;

    // Shift one byte at a time.
    for (std::size_t j = 0; j < 4; ++j) {
      uint8_t b = static_cast<uint8_t>(r >> 24);
      uint32_t g2 = ((b << 1) ^ ((b & 0x80) ? kRsGfFdbk : 0)) & 0xff;
      uint32_t g3 = ((b >> 1) & 0x7f) ^ ((b & 1) ? kRsGfFdbk >> 1 : 0 ) ^ g2;
      r = (r << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
    }
  }

  return r;
}

uint32_t TwofishCipher::F32(uint32_t x, const uint32_t* k32) const {
  static auto p8 = [&](std::size_t x, std::size_t y) -> const uint8_t* {
    // Fixed 8x8 permutation S-boxes.
    static constexpr uint8_t p8x8[2][256] = {
      { 0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78,
        0xe4, 0xdd, 0xd1, 0x38, 0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c,
        0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48, 0xf2, 0xd0, 0x8b, 0x30,
        0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
        0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe,
        0x16, 0x0c, 0xe3, 0x61, 0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b,
        0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1, 0xe1, 0xe6, 0xbd, 0x45,
        0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
        0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf,
        0x33, 0xc9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
        0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7, 0xa1, 0x1d, 0xaa, 0xed,
        0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
        0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b,
        0x5f, 0x93, 0x0a, 0xef, 0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
        0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64, 0x2a, 0xce, 0xcb, 0x2f,
        0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
        0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17,
        0x55, 0x1f, 0x8a, 0x7d, 0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72,
        0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6e, 0x50, 0xde, 0x68,
        0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
        0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42,
        0x4a, 0x5e, 0xc1, 0xe0 },
      { 0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b,
        0x45, 0x7d, 0xe8, 0x4b, 0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1,
        0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f, 0x5e, 0xba, 0xae, 0x5b,
        0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
        0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54,
        0x92, 0x74, 0x36, 0x51, 0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96,
        0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c, 0x13, 0x95, 0x9c, 0xc7,
        0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
        0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf,
        0x40, 0xe7, 0x2b, 0xe2, 0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
        0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17, 0x66, 0x94, 0xa1, 0x1d,
        0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
        0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21,
        0xc4, 0x1a, 0xeb, 0xd9, 0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01,
        0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48, 0x4f, 0xf2, 0x65, 0x8e,
        0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
        0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44,
        0xe0, 0x4d, 0x43, 0x69, 0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e,
        0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc, 0x22, 0xc9, 0xc0, 0x9b,
        0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
        0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56,
        0x55, 0x09, 0xbe, 0x91 }
    };

    static constexpr std::size_t p[4][5] = {
      { 1, 0, 0, 1, 1 },
      { 0, 0, 1, 1, 0 },
      { 1, 1, 0, 0, 0 },
      { 0, 1, 1, 0, 1 }
    };

    return p8x8[p[x][y]];
  };

  // Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. Note
  // that each byte goes through a different combination of S-boxes.
  uint8_t* b = reinterpret_cast<uint8_t*>(&x);
  for (std::size_t i = 0; i < 4; ++i) {
    b[i] = p8(i, 4)[b[i]] ^ reinterpret_cast<const uint8_t*>(&k32[3])[i];
    b[i] = p8(i, 3)[b[i]] ^ reinterpret_cast<const uint8_t*>(&k32[2])[i];
    b[i] = p8(i, 0)[p8(i, 1)[p8(i, 2)[b[i]] ^
        reinterpret_cast<const uint8_t*>(&k32[1])[i]] ^
        reinterpret_cast<const uint8_t*>(&k32[0])[i]];
  }

  // Now perform the MDS matrix multiply inline.
  static constexpr uint32_t kMdsGfFdbk = 0x169;

  auto lfsr1 = [](uint8_t x) -> uint8_t {
    return (x >> 1) ^ ((x & 0x01) ? kMdsGfFdbk / 2 : 0);
  };
  auto lfsr2 = [](uint8_t x) -> uint8_t {
    return (x >> 2) ^ ((x & 0x02) ? kMdsGfFdbk / 2 : 0) ^
        ((x & 0x01) ? kMdsGfFdbk / 4 : 0);
  };

  auto mx_x = [lfsr2](uint8_t x) -> uint8_t {
    return x ^ lfsr2(x);
  };
  auto mx_y = [lfsr1, lfsr2](uint8_t x) -> uint8_t {
    return x ^ lfsr1(x) ^ lfsr2(x);
  };

  uint8_t m[4][4] = {
    {      b[0] , mx_y(b[1]), mx_x(b[2]), mx_x(b[3]) },
    { mx_x(b[0]), mx_y(b[1]), mx_y(b[2]),      b[3]  },
    { mx_y(b[0]), mx_x(b[1]),      b[2] , mx_y(b[3]) },
    { mx_y(b[0]),      b[1] , mx_y(b[2]), mx_x(b[3]) }
  };

  uint32_t res = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    for (std::size_t j = 0; j < 4; ++j)
      res ^= m[i][j] << (i * 8);
  }

  return res;
}

void TwofishCipher::InitializeKey(const std::array<uint8_t, 32>& key) {
  static const uint32_t kSubKeyStep = 0x02020202;
  static const uint32_t kSubKeyBump = 0x01010101;

  // Generate round subkeys.
  int num_subkeys = 8 + 2 * kNumRounds;
  uint32_t k32e[4], k32o[4];

  for (std::size_t i = 0; i < 4; ++i) {
    // Split into even/odd key dwords.
    k32e[i] = reinterpret_cast<const uint32_t*>(key.data())[2 * i];
    k32o[i] = reinterpret_cast<const uint32_t*>(key.data())[2 * i + 1];

    // Compute S-box keys using (12,8) Reed-Solomon code over GF(256).
    key_.sbox_keys[4 - 1 - i] = ReedSolomonEncode(k32e[i], k32o[i]);
  }

  // Compute round subkeys for PHT.
  for (int i = 0; i < num_subkeys / 2; ++i) {
    uint32_t a = F32(i * kSubKeyStep, k32e);
    uint32_t b = F32(i * kSubKeyStep + kSubKeyBump, k32o);
    b = RotateLeft(b, 8);
    key_.sub_keys[2 * i] = a + b;   // Combine with a PHT.
    key_.sub_keys[2 * i + 1] = RotateLeft(a + 2 * b, 9);
  }
}

TwofishCipher::TwofishCipher(const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 16>& init_vec) :
    init_vec_(init_vec) {
  InitializeKey(key);
}

void TwofishCipher::Decrypt(const std::array<uint8_t, 16>& src,
                            std::array<uint8_t, 16>& dst) const {
  uint32_t* dst_ptr = reinterpret_cast<uint32_t*>(dst.data());

  // Copy in the block, add whitening.
  for (std::size_t i = 0; i < 4; ++i) {
    dst_ptr[i] = reinterpret_cast<const uint32_t*>(src.data())[i] ^
        key_.sub_keys[i + 4];
  }

  // Main Twofish decryption loop.
  for (std::size_t r = kNumRounds; r-- > 0;) {
    uint32_t t0 = F32(dst_ptr[0],key_.sbox_keys);
    uint32_t t1 = F32(RotateLeft(dst_ptr[1], 8), key_.sbox_keys);

    dst_ptr[2] = RotateLeft(dst_ptr[2], 1);
    dst_ptr[2] ^= t0 + t1 + key_.sub_keys[8 + 2 * r];   // PHT, round keys.
    dst_ptr[3] ^= t0 + 2 * t1 + key_.sub_keys[8 + 2 * r + 1];
    dst_ptr[3] = RotateRight(dst_ptr[3], 1);

    // Unswap, except for last round.
    if (r) {
      t0 = dst_ptr[0]; dst_ptr[0] = dst_ptr[2]; dst_ptr[2] = t0;
      t1 = dst_ptr[1]; dst_ptr[1] = dst_ptr[3]; dst_ptr[3] = t1;
    }
  }

  // Copy out, with whitening.
  for (std::size_t i = 0; i < 4; ++i)
    dst_ptr[i] ^= key_.sub_keys[i];
}

void TwofishCipher::Encrypt(const std::array<uint8_t, 16>& src,
                            std::array<uint8_t, 16>& dst) const {
  uint32_t* dst_ptr = reinterpret_cast<uint32_t*>(dst.data());

  // Copy in the block, add whitening.
  for (std::size_t i = 0; i < 4; ++i) {
    dst_ptr[i] = reinterpret_cast<const uint32_t*>(src.data())[i] ^
        key_.sub_keys[i];
  }

  // Main Twofish encryption loop.
  uint32_t tmp = 0;
  for (std::size_t r = 0; r < kNumRounds; ++r) {
    uint32_t t0 = F32(dst_ptr[0], key_.sbox_keys);
    uint32_t t1 = F32(RotateLeft(dst_ptr[1], 8), key_.sbox_keys);

    dst_ptr[3] = RotateLeft(dst_ptr[3], 1);
    dst_ptr[2] ^= t0 + t1 + key_.sub_keys[8 + 2 * r];   // PHT, round keys.
    dst_ptr[3] ^= t0 + 2 * t1 + key_.sub_keys[8 + 2 * r + 1];
    dst_ptr[2] = RotateRight(dst_ptr[2], 1);

    // Swap for next round.
    if (r < kNumRounds-1) {
      tmp = dst_ptr[0]; dst_ptr[0] = dst_ptr[2]; dst_ptr[2] = tmp;
      tmp = dst_ptr[1]; dst_ptr[1] = dst_ptr[3]; dst_ptr[3] = tmp;
    }
  }

  // Copy out, with whitening.
  for (std::size_t i = 0; i < 4; ++i)
    dst_ptr[i] ^= key_.sub_keys[i + 4];
}

Salsa20Cipher::Salsa20Cipher(const std::array<uint8_t, 32>& key,
                             const std::array<uint8_t, 8>& init_vec) {
  static const char* kSigma = "expand 32-byte k";

  const uint8_t* key_ptr = key.data();

  input_[1] = *reinterpret_cast<const uint32_t*>(key_ptr + 0);
  input_[2] = *reinterpret_cast<const uint32_t*>(key_ptr + 4);
  input_[3] = *reinterpret_cast<const uint32_t*>(key_ptr + 8);
  input_[4] = *reinterpret_cast<const uint32_t*>(key_ptr + 12);

  input_[11] = *reinterpret_cast<const uint32_t*>(key_ptr + 16);
  input_[12] = *reinterpret_cast<const uint32_t*>(key_ptr + 20);
  input_[13] = *reinterpret_cast<const uint32_t*>(key_ptr + 24);
  input_[14] = *reinterpret_cast<const uint32_t*>(key_ptr + 28);
  input_[0] = *reinterpret_cast<const uint32_t*>(kSigma + 0);
  input_[5] = *reinterpret_cast<const uint32_t*>(kSigma + 4);
  input_[10] = *reinterpret_cast<const uint32_t*>(kSigma + 8);
  input_[15] = *reinterpret_cast<const uint32_t*>(kSigma + 12);

  input_[6] = *reinterpret_cast<const uint32_t*>(init_vec.data() + 0);
  input_[7] = *reinterpret_cast<const uint32_t*>(init_vec.data() + 4);
  input_[8] = 0;
  input_[9] = 0;
}

std::array<uint8_t, 64> Salsa20Cipher::WordToByte(
    const std::array<uint32_t, 16>& input) const {
  uint32_t x[16];

  for (std::size_t i = 0; i < 16; ++i)
    x[i] = input[i];

  for (std::size_t i = 0; i < 10; ++i) {
    x[ 4] ^= RotateLeft(x[ 0] + x[12],  7);
    x[ 8] ^= RotateLeft(x[ 4] + x[ 0],  9);
    x[12] ^= RotateLeft(x[ 8] + x[ 4], 13);
    x[ 0] ^= RotateLeft(x[12] + x[ 8], 18);
    x[ 9] ^= RotateLeft(x[ 5] + x[ 1],  7);
    x[13] ^= RotateLeft(x[ 9] + x[ 5],  9);
    x[ 1] ^= RotateLeft(x[13] + x[ 9], 13);
    x[ 5] ^= RotateLeft(x[ 1] + x[13], 18);
    x[14] ^= RotateLeft(x[10] + x[ 6],  7);
    x[ 2] ^= RotateLeft(x[14] + x[10],  9);
    x[ 6] ^= RotateLeft(x[ 2] + x[14], 13);
    x[10] ^= RotateLeft(x[ 6] + x[ 2], 18);
    x[ 3] ^= RotateLeft(x[15] + x[11],  7);
    x[ 7] ^= RotateLeft(x[ 3] + x[15],  9);
    x[11] ^= RotateLeft(x[ 7] + x[ 3], 13);
    x[15] ^= RotateLeft(x[11] + x[ 7], 18);
    x[ 1] ^= RotateLeft(x[ 0] + x[ 3],  7);
    x[ 2] ^= RotateLeft(x[ 1] + x[ 0],  9);
    x[ 3] ^= RotateLeft(x[ 2] + x[ 1], 13);
    x[ 0] ^= RotateLeft(x[ 3] + x[ 2], 18);
    x[ 6] ^= RotateLeft(x[ 5] + x[ 4],  7);
    x[ 7] ^= RotateLeft(x[ 6] + x[ 5],  9);
    x[ 4] ^= RotateLeft(x[ 7] + x[ 6], 13);
    x[ 5] ^= RotateLeft(x[ 4] + x[ 7], 18);
    x[11] ^= RotateLeft(x[10] + x[ 9],  7);
    x[ 8] ^= RotateLeft(x[11] + x[10],  9);
    x[ 9] ^= RotateLeft(x[ 8] + x[11], 13);
    x[10] ^= RotateLeft(x[ 9] + x[ 8], 18);
    x[12] ^= RotateLeft(x[15] + x[14],  7);
    x[13] ^= RotateLeft(x[12] + x[15],  9);
    x[14] ^= RotateLeft(x[13] + x[12], 13);
    x[15] ^= RotateLeft(x[14] + x[13], 18);
  }

  for (std::size_t i = 0; i < 16; ++i)
    x[i] = x[i] + input[i];

  std::array<uint8_t, 64> output;
  for (std::size_t i = 0; i < 16; ++i)
    *reinterpret_cast<uint32_t*>(output.data() + 4 * i) = x[i];

  return output;
}

void Salsa20Cipher::Process(const std::array<uint8_t, 64>& src,
                            std::array<uint8_t, 64>& dst) {
  std::array<uint8_t, 64> output = WordToByte(input_);

  input_[8]++;
  if (!input_[8])
    input_[9]++;

  for (std::size_t i = 0; i < src.size(); ++i)
    dst[i] = src[i] ^ output[i];
}

}   // namespace keepass
