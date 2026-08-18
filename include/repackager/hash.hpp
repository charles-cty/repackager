#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

using Sha256Digest = std::array<std::uint8_t, 32>;

Sha256Digest sha256_bytes(const void* data, std::size_t size);
Sha256Digest sha256_string(std::string_view text);
Sha256Digest sha256_file(const std::filesystem::path& path);

std::string to_hex(const Sha256Digest& digest);
std::string sha256_file_hex(const std::filesystem::path& path);

std::vector<std::uint8_t> utf16le(std::string_view utf8);

}  // namespace repackager
