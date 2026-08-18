#include "repackager/stage.hpp"

#include "repackager/hash.hpp"
#include "repackager/paths.hpp"

#include <fstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace repackager {
namespace {

#ifdef _WIN32
void copy_win_attributes(const std::filesystem::path& from, const std::filesystem::path& to) {
  const DWORD attr = GetFileAttributesW(from.c_str());
  if (attr != INVALID_FILE_ATTRIBUTES) {
    SetFileAttributesW(to.c_str(), attr);
  }
}
#endif

bool excluded(const std::filesystem::path& rel, const std::vector<std::string>& names) {
  const auto generic = rel.generic_string();
  for (const auto& n : names) {
    if (generic == n || rel.filename() == n) return true;
    if (generic.size() >= n.size() && generic.compare(0, n.size(), n) == 0 &&
        (generic.size() == n.size() || generic[n.size()] == '/')) {
      return true;
    }
  }
  return false;
}

Status copy_one_file(const std::filesystem::path& from, const std::filesystem::path& to,
                     const StageOptions& options, StageResult& result,
                     OperationJournal* journal) {
  if (options.reject_reparse && is_reparse_or_symlink(from)) {
    return Status::fail(ExitCode::Validation, "refusing reparse point: " + from.string());
  }
  std::error_code ec;
  if (std::filesystem::exists(to, ec)) {
    return Status::fail(ExitCode::Conflict, "destination already exists: " + to.string());
  }
  std::filesystem::create_directories(to.parent_path(), ec);
  if (auto st = fault_checkpoint("stage-before-copy"); !st) return st;
  std::filesystem::copy_file(from, to, std::filesystem::copy_options::none, ec);
  if (ec) {
    return Status::fail(ExitCode::Internal,
                        "copy failed: " + from.string() + " -> " + to.string() + ": " +
                            ec.message());
  }
  if (options.preserve_timestamps) {
    auto t = std::filesystem::last_write_time(from, ec);
    if (!ec) std::filesystem::last_write_time(to, t, ec);
  }
#ifdef _WIN32
  if (options.preserve_attributes) copy_win_attributes(from, to);
#endif
  CreatedPath cp;
  cp.path = to.string();
  cp.sha256 = sha256_file_hex(to);
  result.copied.push_back(cp);
  result.file_count += 1;
  result.byte_count += std::filesystem::file_size(to, ec);
  if (journal) journal_record_path(*journal, to);
  if (auto st = fault_checkpoint("stage-after-copy"); !st) return st;
  return Status::success();
}

}  // namespace

std::vector<std::string> default_msix_footprint_excludes() {
  return {"AppxBlockMap.xml", "AppxSignature.p7x", "[Content_Types].xml", "AppxMetadata",
          "AppxManifest.xml"};
}

Expected<StageResult> stage_files(const StageOptions& options, OperationJournal* journal) {
  StageResult result;
  std::error_code ec;
  if (!std::filesystem::exists(options.source, ec) ||
      !std::filesystem::is_directory(options.source, ec)) {
    return Expected<StageResult>::fail(ExitCode::NotFound,
                                       "source directory not found: " + options.source.string());
  }
  if (options.reject_reparse && is_reparse_or_symlink(options.source)) {
    return Expected<StageResult>::fail(ExitCode::Validation,
                                       "refusing reparse-point source directory");
  }

  std::filesystem::create_directories(options.destination, ec);
  if (journal) journal_record_path(*journal, options.destination);

  for (auto it = std::filesystem::recursive_directory_iterator(
           options.source, std::filesystem::directory_options::skip_permission_denied, ec);
       it != std::filesystem::recursive_directory_iterator(); ++it) {
    const auto& entry = *it;
    const auto rel = std::filesystem::relative(entry.path(), options.source, ec);
    if (excluded(rel, options.exclude_names)) {
      if (entry.is_directory()) it.disable_recursion_pending();
      continue;
    }
    if (!path_contained(options.source, entry.path())) {
      return Expected<StageResult>::fail(ExitCode::Validation,
                                         "source entry escapes tree: " + entry.path().string());
    }
    if (options.reject_reparse && is_reparse_or_symlink(entry.path())) {
      return Expected<StageResult>::fail(ExitCode::Validation,
                                         "refusing reparse point: " + entry.path().string());
    }
    const auto dest = options.destination / rel;
    if (!path_contained(options.destination, dest)) {
      return Expected<StageResult>::fail(ExitCode::Validation, "destination path escapes output");
    }
    if (entry.is_directory()) {
      std::filesystem::create_directories(dest, ec);
      if (journal) journal_record_path(*journal, dest);
      continue;
    }
    if (!entry.is_regular_file()) continue;
    auto st = copy_one_file(entry.path(), dest, options, result, journal);
    if (!st) return Expected<StageResult>::fail(st.code, st.message);
  }
  return Expected<StageResult>::ok(std::move(result));
}

}  // namespace repackager
