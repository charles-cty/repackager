#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace repackager::test {

struct PeBuildOptions {
  bool pe32plus = true;
  std::uint16_t machine = 0x8664;  // AMD64
  std::string manifest;
  bool authenticode = false;
  std::string file_version;  // unused unless version resource requested
};

bool write_minimal_pe(const std::filesystem::path& path, const PeBuildOptions& options);

}  // namespace repackager::test
