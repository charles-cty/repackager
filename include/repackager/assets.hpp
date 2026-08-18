#pragma once

#include "repackager/error.hpp"
#include "repackager/journal.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace repackager {

struct AssetSet {
  std::filesystem::path store_logo;
  std::filesystem::path square44;
  std::filesystem::path square150;
  std::vector<CreatedPath> created;
  bool from_exe_icon = false;
};

// Extract the selected EXE icon via WIC when available; otherwise write
// deterministic placeholder PNGs seeded by `seed`.
Expected<AssetSet> generate_assets(const std::filesystem::path& output_dir,
                                   const std::filesystem::path& exe,
                                   std::string_view seed,
                                   OperationJournal* journal = nullptr);

std::vector<std::uint8_t> make_placeholder_png(int width, int height,
                                               std::string_view seed);

#ifdef _WIN32
bool try_extract_exe_icon_wic(const std::filesystem::path& exe,
                              const std::filesystem::path& output_dir,
                              AssetSet& set);
#endif

}  // namespace repackager
