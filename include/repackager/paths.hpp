#pragma once

#include "repackager/error.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

std::filesystem::path normalize_path(const std::filesystem::path& path);
bool is_absolute_path(const std::filesystem::path& path);

// True when `candidate` is `root` or a descendant after normalization.
// Rejects `..` escapes and alternate-stream / device tricks we can see.
bool path_contained(const std::filesystem::path& root,
                    const std::filesystem::path& candidate);

Status check_path_contained(const std::filesystem::path& root,
                            const std::filesystem::path& candidate);

bool is_reparse_or_symlink(const std::filesystem::path& path);
bool directory_is_absent_or_empty(const std::filesystem::path& path);

std::filesystem::path default_data_root();
std::filesystem::path receipts_root();
std::filesystem::path receipt_dir_for(std::string_view package_name);
std::filesystem::path elevate_request_dir();

std::string native_string(const std::filesystem::path& path);
std::filesystem::path make_relative(const std::filesystem::path& root,
                                    const std::filesystem::path& path);

std::string join_win(std::string_view a, std::string_view b);

}  // namespace repackager
