#include "repackager/paths.hpp"

#include <cstdlib>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace repackager {
namespace {

std::filesystem::path lexically_normal_generic(const std::filesystem::path& path) {
  return path.lexically_normal();
}

#ifdef _WIN32
bool has_reparse_attribute(const std::filesystem::path& path) {
  const DWORD attr = GetFileAttributesW(path.c_str());
  if (attr == INVALID_FILE_ATTRIBUTES) return false;
  return (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}
#endif

}  // namespace

std::filesystem::path normalize_path(const std::filesystem::path& path) {
  std::error_code ec;
  auto abs = std::filesystem::absolute(path, ec);
  if (ec) abs = path;
  return lexically_normal_generic(abs);
}

bool is_absolute_path(const std::filesystem::path& path) { return path.is_absolute(); }

bool path_contained(const std::filesystem::path& root, const std::filesystem::path& candidate) {
  const auto nroot = normalize_path(root);
  const auto ncand = normalize_path(candidate);
  const auto rel = ncand.lexically_relative(nroot);
  if (rel.empty()) return false;
  for (const auto& part : rel) {
    if (part == "..") return false;
  }
  // Reject Windows alternate data streams in the relative tail.
  const auto generic = rel.generic_string();
  if (generic.find(':') != std::string::npos) return false;
  return true;
}

Status check_path_contained(const std::filesystem::path& root,
                            const std::filesystem::path& candidate) {
  if (!path_contained(root, candidate)) {
    return Status::fail(ExitCode::Validation,
                        "path escapes root: " + candidate.string());
  }
  return Status::success();
}

bool is_reparse_or_symlink(const std::filesystem::path& path) {
  std::error_code ec;
  if (std::filesystem::is_symlink(path, ec)) return true;
#ifdef _WIN32
  if (has_reparse_attribute(path)) return true;
#endif
  return false;
}

bool directory_is_absent_or_empty(const std::filesystem::path& path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) return true;
  if (!std::filesystem::is_directory(path, ec)) return false;
  return std::filesystem::directory_iterator(path, ec) ==
         std::filesystem::directory_iterator{};
}

std::filesystem::path default_data_root() {
  if (const char* override_dir = std::getenv("REPACKAGER_DATA_DIR")) {
    if (*override_dir) return std::filesystem::path(override_dir);
  }
#ifdef _WIN32
  if (const char* local = std::getenv("LOCALAPPDATA")) {
    if (*local) return std::filesystem::path(local) / "Repackager";
  }
  return std::filesystem::temp_directory_path() / "Repackager";
#else
  if (const char* xdg = std::getenv("XDG_DATA_HOME")) {
    if (*xdg) return std::filesystem::path(xdg) / "Repackager";
  }
  return std::filesystem::temp_directory_path() / "Repackager";
#endif
}

std::filesystem::path receipts_root() { return default_data_root() / "receipts"; }

std::filesystem::path receipt_dir_for(std::string_view package_name) {
  return receipts_root() / std::string(package_name);
}

std::filesystem::path elevate_request_dir() { return default_data_root() / "elevate"; }

std::string native_string(const std::filesystem::path& path) { return path.string(); }

std::filesystem::path make_relative(const std::filesystem::path& root,
                                    const std::filesystem::path& path) {
  return normalize_path(path).lexically_relative(normalize_path(root));
}

std::string join_win(std::string_view a, std::string_view b) {
  if (a.empty()) return std::string(b);
  if (b.empty()) return std::string(a);
  if (a.back() == '\\' || a.back() == '/') {
    return std::string(a) + std::string(b);
  }
  return std::string(a) + "\\" + std::string(b);
}

std::string win_relative_path(const std::filesystem::path& path) {
  auto s = path.generic_string();
  while (s.size() >= 2 && s[0] == '.' && (s[1] == '/' || s[1] == '\\')) s.erase(0, 2);
  while (!s.empty() && (s.front() == '/' || s.front() == '\\')) s.erase(s.begin());
  for (char& c : s)
    if (c == '/') c = '\\';
  return s;
}

Status validate_package_relative_executable(std::string_view executable) {
  if (executable.empty()) {
    return Status::fail(ExitCode::Validation, "Executable must be a package-relative path");
  }
  for (unsigned char c : executable) {
    if (c < 0x20 || c == '<' || c == '>' || c == '"' || c == ':' || c == '%' || c == '|' ||
        c == '?' || c == '*') {
      return Status::fail(ExitCode::Validation,
                          "Executable must be package-relative (got '" + std::string(executable) +
                              "'); pass a path inside the source directory, not a drive path");
    }
  }
  return Status::success();
}

Expected<ResolvedExecutable> resolve_executable_under_root(
    const std::filesystem::path& root, const std::filesystem::path& executable) {
  if (root.empty() || executable.empty()) {
    return Expected<ResolvedExecutable>::fail(ExitCode::Usage, "executable path is empty");
  }
  const auto candidate = executable.is_absolute() ? executable : (root / executable);
  if (!path_contained(root, candidate)) {
    return Expected<ResolvedExecutable>::fail(ExitCode::Validation,
                                              "executable escapes package directory");
  }
  auto rel = make_relative(root, candidate);
  if (rel.empty() || rel == "." || rel == "..") {
    return Expected<ResolvedExecutable>::fail(
        ExitCode::Validation, "executable must be a file inside the package directory");
  }
  for (const auto& part : rel) {
    if (part == "..") {
      return Expected<ResolvedExecutable>::fail(ExitCode::Validation,
                                                "executable escapes package directory");
    }
  }
  ResolvedExecutable out;
  out.relative = rel;
  out.absolute = normalize_path(candidate);
  out.manifest = win_relative_path(rel);
  if (auto st = validate_package_relative_executable(out.manifest); !st) {
    return Expected<ResolvedExecutable>::fail(st.code, st.message);
  }
  std::error_code ec;
  if (!std::filesystem::is_regular_file(out.absolute, ec)) {
    return Expected<ResolvedExecutable>::fail(ExitCode::NotFound,
                                              "executable not found: " + out.absolute.string());
  }
  return Expected<ResolvedExecutable>::ok(std::move(out));
}

}  // namespace repackager
