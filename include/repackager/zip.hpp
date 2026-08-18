#pragma once

#include "repackager/error.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace repackager {

struct ZipEntry {
  std::string name;
  std::vector<std::uint8_t> data;
  bool is_directory = false;
};

Expected<std::vector<ZipEntry>> zip_read(const std::filesystem::path& path);
Status zip_write(const std::filesystem::path& path, const std::vector<ZipEntry>& entries);

}  // namespace repackager
