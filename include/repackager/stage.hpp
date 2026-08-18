#pragma once

#include "repackager/error.hpp"
#include "repackager/journal.hpp"
#include "repackager/models.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace repackager {

struct StageOptions {
  std::filesystem::path source;
  std::filesystem::path destination;
  bool reject_reparse = true;
  bool preserve_timestamps = true;
  bool preserve_attributes = true;
  std::vector<std::string> exclude_names;  // footprint files, etc.
};

struct StageResult {
  std::vector<CreatedPath> copied;
  std::uint64_t file_count = 0;
  std::uint64_t byte_count = 0;
};

// Copy a tree with reparse-point rejection, collision detection, preserved
// timestamps/attributes, and no source mutation. Never overwrites nonempty
// destination files.
Expected<StageResult> stage_files(const StageOptions& options,
                                  OperationJournal* journal = nullptr);

std::vector<std::string> default_msix_footprint_excludes();

}  // namespace repackager
