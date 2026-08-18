#include "repackager/assets.hpp"
#include "repackager/hash.hpp"
#include "repackager/journal.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <fstream>

using namespace repackager;

TEST(generate_assets_records_placeholder_pngs) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-assets-ph";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto dir = root / "Assets";
  OperationJournal journal;
  journal.operation_id = "assets-ph";
  journal.journal_path = (root / "journal.json").string();
  auto set = generate_assets(dir, {}, "Contoso.Assets", &journal);
  CHECK(set);
  CHECK(std::filesystem::exists(set.value().store_logo));
  CHECK(std::filesystem::exists(set.value().square44));
  CHECK(std::filesystem::exists(set.value().square150));
  CHECK_EQ(set.value().created.size(), static_cast<std::size_t>(3));
  CHECK_EQ(journal.created_paths.size(), static_cast<std::size_t>(3));
  for (const auto& c : set.value().created) {
    CHECK(std::filesystem::exists(c.path));
    CHECK(!c.sha256.empty());
  }
  std::filesystem::remove_all(root, ec);
}

TEST(generate_assets_records_preexisting_wic_pngs) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-assets-wic";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto dir = root / "Assets";
  std::filesystem::create_directories(dir, ec);
  // Simulate WIC already writing the three logos (write_png used to skip these).
  const auto store = dir / "StoreLogo.png";
  const auto sq44 = dir / "Square44x44Logo.png";
  const auto sq150 = dir / "Square150x150Logo.png";
  {
    std::ofstream(store, std::ios::binary) << "WIC-STORE";
    std::ofstream(sq44, std::ios::binary) << "WIC-44";
    std::ofstream(sq150, std::ios::binary) << "WIC-150";
  }
  const auto store_hash = sha256_file_hex(store);
  OperationJournal journal;
  journal.operation_id = "assets-wic";
  auto set = generate_assets(dir, {}, "Contoso.Wic", &journal);
  CHECK(set);
  CHECK_EQ(set.value().created.size(), static_cast<std::size_t>(3));
  CHECK_EQ(journal.created_paths.size(), static_cast<std::size_t>(3));
  bool saw_store = false;
  for (const auto& c : set.value().created) {
    if (std::filesystem::path(c.path).filename() == "StoreLogo.png") {
      saw_store = true;
      CHECK_EQ(c.sha256, store_hash);
    }
  }
  CHECK(saw_store);
  // Pre-existing WIC bytes must not be overwritten by placeholders.
  CHECK_EQ(sha256_file_hex(store), store_hash);
  std::filesystem::remove_all(root, ec);
}
