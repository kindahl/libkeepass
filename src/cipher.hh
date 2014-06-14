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
#include <cassert>
#include <cstdint>
#include <memory>
#include <iostream>

#include <openssl/aes.h>

namespace keepass {

template <std::size_t N>
class Cipher;

std::array<uint8_t, 32> encrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher);
std::array<uint8_t, 32> decrypt_ecb(const std::array<uint8_t, 32>& src,
                                    const Cipher<16>& cipher);
void encrypt_cbc(std::istream& src, std::ostream& dst,
                 const Cipher<16>& cipher);
void decrypt_cbc(std::istream& src, std::ostream& dst,
                 const Cipher<16>& cipher);

template <std::size_t N>
class Cipher {
 public:
  virtual ~Cipher() = default;

  virtual const std::array<uint8_t, N>& InitializationVector() const = 0;

  virtual void Decrypt(const std::array<uint8_t, N>& src,
                       std::array<uint8_t, N>& dst) const = 0;
  virtual void Encrypt(const std::array<uint8_t, N>& src,
                       std::array<uint8_t, N>& dst) const = 0;
};

class AesCipher final : public Cipher<16> {
 private:
  const std::array<uint8_t, 16> init_vec_;
  AES_KEY key_dec_;
  AES_KEY key_enc_;

 public:
  AesCipher(const std::array<uint8_t, 32>& key) :
    AesCipher(key, { 0 }) {}
  AesCipher(const std::array<uint8_t, 32>& key,
            const std::array<uint8_t, 16>& init_vec);

  const std::array<uint8_t, 16>& InitializationVector() const override {
    return init_vec_;
  }

  virtual void Decrypt(const std::array<uint8_t, 16>& src,
                       std::array<uint8_t, 16>& dst) const override;
  virtual void Encrypt(const std::array<uint8_t, 16>& src,
                       std::array<uint8_t, 16>& dst) const override;
};

class TwofishCipher final : public Cipher<16> {
 private:
  static const uint8_t kNumRounds = 16;

  struct Key {
    /** Key bits used for S-boxes. */
    uint32_t sbox_keys[4];
    /** Round subkeys, input/output whitening bits. */
    uint32_t sub_keys[40];
  } key_;

  const std::array<uint8_t, 16> init_vec_;

  inline uint32_t RotateLeft(uint32_t v, uint32_t n) const {
    return (v << (n & 0x1f)) | (v >> (32 - (n & 0x1f)));
  }

  inline uint32_t RotateRight(uint32_t v, uint32_t n) const {
    return (v >> (n & 0x1f)) | (v << (32 - (n & 0x1f)));
  }

  uint32_t ReedSolomonEncode(uint32_t k0, uint32_t k1) const;
  uint32_t F32(uint32_t x, const uint32_t* k32) const;

  void InitializeKey(const std::array<uint8_t, 32>& key);

 public:
  TwofishCipher(const std::array<uint8_t, 32>& key) :
    TwofishCipher(key, { 0 }) {}
  TwofishCipher(const std::array<uint8_t, 32>& key,
                const std::array<uint8_t, 16>& init_vec);

  const std::array<uint8_t, 16>& InitializationVector() const override {
    return init_vec_;
  }

  virtual void Decrypt(const std::array<uint8_t, 16>& src,
                       std::array<uint8_t, 16>& dst) const override;
  virtual void Encrypt(const std::array<uint8_t, 16>& src,
                       std::array<uint8_t, 16>& dst) const override;
};

/**
 * @brief Salsa20 stream cipher implementation.
 */
class Salsa20Cipher final {
 private:
  std::array<uint32_t, 16> input_ = { { 0 } };

  inline uint32_t RotateLeft(uint32_t v, uint32_t n) const {
    return (v << (n & 0x1f)) | (v >> (32 - (n & 0x1f)));
  }

  std::array<uint8_t, 64> WordToByte(
      const std::array<uint32_t, 16>& input) const;

 public:
  Salsa20Cipher(const std::array<uint8_t, 32>& key) :
    Salsa20Cipher(key, { 0 }) {}
  Salsa20Cipher(const std::array<uint8_t, 32>& key,
                const std::array<uint8_t, 8>& init_vec);

  void Process(const std::array<uint8_t, 64>& src,
               std::array<uint8_t, 64>& dst);
};

}
