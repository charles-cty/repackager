#include "repackager/paths.hpp"
#include "test_support.hpp"

#include <filesystem>

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
