#include "repackager/paths.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <fstream>

using namespace repackager;

TEST(path_containment_accepts_descendants) {
  const auto root = std::filesystem::path("/tmp/repackager-root");
  CHECK(path_contained(root, root / "a" / "b.exe"));
  CHECK(path_contained(root, root));
}

TEST(path_containment_rejects_escape) {
  const auto root = std::filesystem::path("/tmp/repackager-root");
  CHECK(!path_contained(root, root / ".." / "etc" / "passwd"));
  CHECK(!path_contained(root, std::filesystem::path("/etc/passwd")));
  auto st = check_path_contained(root, root / ".." / "x");
  CHECK(!st);
  CHECK(st.code == ExitCode::Validation);
}

TEST(resolve_executable_accepts_absolute_inside_root) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-exe-abs";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  std::filesystem::create_directories(root / "bin", ec);
  const auto exe = root / "bin" / "ZCode.exe";
  {
    std::ofstream out(exe, std::ios::binary);
    out << "MZ";
  }
  auto r = resolve_executable_under_root(root, exe);
  CHECK(r);
  CHECK_EQ(r.value().manifest, std::string("bin\\ZCode.exe"));
  CHECK_EQ(r.value().relative, std::filesystem::path("bin") / "ZCode.exe");
  auto rel = resolve_executable_under_root(root, std::filesystem::path("bin") / "ZCode.exe");
  CHECK(rel);
  CHECK_EQ(rel.value().manifest, std::string("bin\\ZCode.exe"));
  auto outside = resolve_executable_under_root(root, std::filesystem::temp_directory_path() /
                                                         "repackager-exe-other" / "x.exe");
  CHECK(!outside);
  CHECK(outside.code() == ExitCode::Validation);
  auto st = validate_package_relative_executable(R"(C:\Program Files\ZCode\ZCode.exe)");
  CHECK(!st);
  CHECK(st.code == ExitCode::Validation);
  CHECK(validate_package_relative_executable("ZCode.exe"));
  std::filesystem::remove_all(root, ec);
}
