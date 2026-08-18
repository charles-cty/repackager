#include "repackager/hash.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace repackager {
namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

void sha256_transform(std::uint32_t state[8], const std::uint8_t block[64]) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           (static_cast<std::uint32_t>(block[i * 4 + 3]));
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
  for (int i = 0; i < 64; ++i) {
    const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + S1 + ch + kK[i] + w[i];
    const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

}  // namespace

Sha256Digest sha256_bytes(const void* data, std::size_t size) {
  std::uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint8_t block[64];
  std::size_t offset = 0;
  while (size - offset >= 64) {
    sha256_transform(state, bytes + offset);
    offset += 64;
  }
  std::size_t rem = size - offset;
  std::copy(bytes + offset, bytes + size, block);
  block[rem] = 0x80;
  if (rem >= 56) {
    std::fill(block + rem + 1, block + 64, static_cast<std::uint8_t>(0));
    sha256_transform(state, block);
    std::fill(block, block + 56, static_cast<std::uint8_t>(0));
  } else {
    std::fill(block + rem + 1, block + 56, static_cast<std::uint8_t>(0));
  }
  const std::uint64_t bit_len = static_cast<std::uint64_t>(size) * 8;
  for (int i = 0; i < 8; ++i) {
    block[63 - i] = static_cast<std::uint8_t>(bit_len >> (i * 8));
  }
  sha256_transform(state, block);

  Sha256Digest out{};
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(state[i] >> 24);
    out[i * 4 + 1] = static_cast<std::uint8_t>(state[i] >> 16);
    out[i * 4 + 2] = static_cast<std::uint8_t>(state[i] >> 8);
    out[i * 4 + 3] = static_cast<std::uint8_t>(state[i]);
  }
  return out;
}

Sha256Digest sha256_string(std::string_view text) {
  return sha256_bytes(text.data(), text.size());
}

Sha256Digest sha256_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot open file for hashing: " + path.string());
  }
  std::vector<char> buf((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
  return sha256_bytes(buf.data(), buf.size());
}

std::string to_hex(const Sha256Digest& digest) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(64, '0');
  for (int i = 0; i < 32; ++i) {
    out[i * 2] = kHex[digest[i] >> 4];
    out[i * 2 + 1] = kHex[digest[i] & 0x0f];
  }
  return out;
}

std::string sha256_file_hex(const std::filesystem::path& path) {
  return to_hex(sha256_file(path));
}

std::vector<std::uint8_t> utf16le(std::string_view utf8) {
  std::vector<std::uint8_t> out;
  out.reserve(utf8.size() * 2);
  for (std::size_t i = 0; i < utf8.size();) {
    unsigned char c = static_cast<unsigned char>(utf8[i]);
    std::uint32_t cp = 0;
    int n = 1;
    if (c < 0x80) {
      cp = c;
    } else if ((c & 0xe0) == 0xc0 && i + 1 < utf8.size()) {
      cp = ((c & 0x1f) << 6) | (static_cast<unsigned char>(utf8[i + 1]) & 0x3f);
      n = 2;
    } else if ((c & 0xf0) == 0xe0 && i + 2 < utf8.size()) {
      cp = ((c & 0x0f) << 12) |
           ((static_cast<unsigned char>(utf8[i + 1]) & 0x3f) << 6) |
           (static_cast<unsigned char>(utf8[i + 2]) & 0x3f);
      n = 3;
    } else if ((c & 0xf8) == 0xf0 && i + 3 < utf8.size()) {
      cp = ((c & 0x07) << 18) |
           ((static_cast<unsigned char>(utf8[i + 1]) & 0x3f) << 12) |
           ((static_cast<unsigned char>(utf8[i + 2]) & 0x3f) << 6) |
           (static_cast<unsigned char>(utf8[i + 3]) & 0x3f);
      n = 4;
    } else {
      cp = 0xfffd;
    }
    i += n;
    if (cp >= 0x10000) {
      cp -= 0x10000;
      const std::uint16_t hi = static_cast<std::uint16_t>(0xd800 + (cp >> 10));
      const std::uint16_t lo = static_cast<std::uint16_t>(0xdc00 + (cp & 0x3ff));
      out.push_back(static_cast<std::uint8_t>(hi & 0xff));
      out.push_back(static_cast<std::uint8_t>(hi >> 8));
      out.push_back(static_cast<std::uint8_t>(lo & 0xff));
      out.push_back(static_cast<std::uint8_t>(lo >> 8));
    } else {
      const std::uint16_t u = static_cast<std::uint16_t>(cp);
      out.push_back(static_cast<std::uint8_t>(u & 0xff));
      out.push_back(static_cast<std::uint8_t>(u >> 8));
    }
  }
  return out;
}

}  // namespace repackager
