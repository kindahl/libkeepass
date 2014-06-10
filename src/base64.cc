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

#include "base64.hh"

#include <algorithm>
#include <cassert>
#include <locale>
#include <stdexcept>

namespace {
  static const std::string kBase64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/";
}

namespace keepass {

std::string base64_encode(const std::string& src) {
  std::string dst;

  if (src.size() > 1) {
    for (std::size_t i = 0; i < src.size() - 2; i += 3) {
      unsigned char c0 = src[i], c1 = src[i + 1], c2 = src[i + 2];
      dst.push_back(kBase64[c0 >> 2]);
      dst.push_back(kBase64[((c0 & 0x3) << 4) | (c1 >> 4)]);
      dst.push_back(kBase64[((c1 & 0xf) << 2) | (c2 >> 6)]);
      dst.push_back(kBase64[c2 & 0x3f]);
    }
  }

  // Process trail bytes and apply padding if necessary.
  switch (src.size() % 3) {
    case 0:
      break;
    case 1: {
      char c0 = src[src.size() - 1];
      dst.push_back(kBase64[c0 >> 2]);
      dst.push_back(kBase64[((c0 & 0x3) << 4)]);
      dst.push_back('=');
      dst.push_back('=');
      break;
    }
    case 2: {
      char c0 = src[src.size() - 2], c1 = src[src.size() - 1];
      dst.push_back(kBase64[c0 >> 2]);
      dst.push_back(kBase64[((c0 & 0x3) << 4) | (c1 >> 4)]);
      dst.push_back(kBase64[((c1 & 0xf) << 2)]);
      dst.push_back('=');
      break;
    }
    default:
      assert(false);
      break;
  }

  return dst;
}

std::string base64_decode(const std::string& src) {
  std::string src_trimmed;
  std::copy_if(src.begin(), src.end(),
               std::back_inserter<std::string>(src_trimmed),
               [](char c) {
    return !std::isspace(c, std::locale::classic());
  });

  if (src_trimmed.size() % 4 != 0)
    throw std::runtime_error("invalid base64 data.");

  std::string dst;

  uint32_t bits24 = 0;
  std::size_t i = 0;

  for (char c : src_trimmed) {
    if (std::isspace(c))
      continue;

    if (c == '=') {
      dst.push_back(bits24 >> 16);
      if (i > 2)
        dst.push_back((bits24 >> 8) & 0xff);
      if (i > 3)
        dst.push_back(bits24 & 0xff);
      break;
    }

    std::size_t v = kBase64.find(c);
    if (v == std::string::npos)
      throw std::runtime_error("invalid character in base64 stream.");

    bits24 |= static_cast<uint32_t>(v) << (18 - i++ * 6);
    if (i == 4) {
      dst.push_back(bits24 >> 16);
      dst.push_back((bits24 >> 8) & 0xff);
      dst.push_back(bits24 & 0xff);
      bits24 = 0;
      i = 0;
    }
  }

  return dst;
}

}   // namespace keepass
