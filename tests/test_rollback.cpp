#include "pe_builder.hpp"
#include "repackager/assets.hpp"
#include "repackager/cli.hpp"
#include "repackager/hash.hpp"
#include "repackager/journal.hpp"
#include "repackager/manifest.hpp"
#include "repackager/package_io.hpp"
#include "repackager/paths.hpp"
#include "repackager/receipt.hpp"
#include "repackager/register.hpp"
#include "repackager/stage.hpp"
#include "repackager/zip.hpp"
#include "test_support.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using namespace repackager;

TEST(rollback_deletes_only_journal_paths) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-rollback";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  std::filesystem::create_directories(root, ec);
  const auto original = root / "original.exe";
  const auto created = root / "created.txt";
  const auto unrelated = root / "unrelated.txt";
  {
    std::ofstream(original) << "exe";
    std::ofstream(created) << "new";
    std::ofstream(unrelated) << "keep";
  }
  OperationJournal j;
  j.operation_id = "rb-1";
  j.created_paths.push_back(created.string());
  bool unregistered = false;
  RollbackHooks hooks;
  hooks.unregister = [&](std::string_view) {
    unregistered = true;
    return Status::success();
  };
  j.registered = true;
  j.package_full_name = "Pkg_1.0.0.0_neutral__abc";
  auto st = rollback_journal(j, hooks, original);
  CHECK(st);
  CHECK(unregistered);
  CHECK(std::filesystem::exists(original));
  CHECK(std::filesystem::exists(unrelated));
  CHECK(!std::filesystem::exists(created));
  std::filesystem::remove_all(root, ec);
}

TEST(rollback_fault_injection_after_each_stage) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-fault";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto src = root / "src";
  const auto dst = root / "dst";
  std::filesystem::create_directories(src, ec);
  {
    std::ofstream(src / "a.txt") << "hello";
  }
  const std::string stages[] = {"stage-before-copy", "stage-after-copy"};
  for (const auto& stage : stages) {
    std::filesystem::remove_all(dst, ec);
    set_fault_hook([&](std::string_view s) -> Status {
      if (s == stage) return Status::fail(ExitCode::Internal, "injected:" + std::string(s));
      return Status::success();
    });
    OperationJournal journal;
    journal.operation_id = "fault";
    StageOptions opt;
    opt.source = src;
    opt.destination = dst;
    auto r = stage_files(opt, &journal);
    CHECK(!r);
    rollback_journal(journal, {}, {});
    // Source never mutated.
    CHECK(std::filesystem::exists(src / "a.txt"));
    clear_fault_hook();
  }
  std::filesystem::remove_all(root, ec);
}

TEST(rollback_workflow_prepare_fault_after_journal) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-wf-fault";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto src = root / "src";
  const auto out = root / "out";
  std::filesystem::create_directories(src, ec);
  CHECK(test::write_minimal_pe(src / "probe.exe", test::PeBuildOptions{}));
  const auto original_hash = sha256_file_hex(src / "probe.exe");

  set_fault_hook([](std::string_view s) -> Status {
    if (s == "after-journal") return Status::fail(ExitCode::Internal, "boom");
    return Status::success();
  });
  const int code = run_cli(std::vector<std::string>{
      "retrofit-win32-sparse", "--source", src.string(), "--executable", "probe.exe",
      "--output", out.string(), "--name", "Contoso.Fault", "--prepare-only"});
  clear_fault_hook();
  CHECK(code != 0);
  CHECK_EQ(sha256_file_hex(src / "probe.exe"), original_hash);
  // Unrelated file beside the source must remain (there isn't one unless we add it).
  {
    std::ofstream(src / "keep.dat") << "x";
  }
  set_fault_hook([](std::string_view s) -> Status {
    if (s == "stage-after-copy") return Status::fail(ExitCode::Internal, "copy-boom");
    return Status::success();
  });
  const auto out2 = root / "out2";
  const int code2 = run_cli(std::vector<std::string>{
      "retrofit-win32-sparse", "--source", src.string(), "--executable", "probe.exe",
      "--output", out2.string(), "--name", "Contoso.Fault2", "--prepare-only"});
  clear_fault_hook();
  CHECK(code2 != 0);
  CHECK(std::filesystem::exists(src / "keep.dat"));
  CHECK_EQ(sha256_file_hex(src / "probe.exe"), original_hash);
  std::filesystem::remove_all(root, ec);
}

TEST(rollback_removes_nonempty_journaled_directory) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-rb-dir";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto assets = root / "RepackagerAssets" / "op1";
  std::filesystem::create_directories(assets, ec);
  {
    std::ofstream(assets / "StoreLogo.png") << "png";
    std::ofstream(assets / "Square44x44Logo.png") << "png";
  }
  const auto original = root / "probe.exe";
  {
    std::ofstream(original) << "MZ";
  }
  OperationJournal j;
  j.operation_id = "rb-dir";
  // Old WF2 order: files first, directory last. remove() on a full dir used to leave it.
  j.created_paths.push_back((assets / "StoreLogo.png").string());
  j.created_paths.push_back((assets / "Square44x44Logo.png").string());
  j.created_paths.push_back(assets.string());
  j.created_paths.push_back((root / "RepackagerAssets").string());
  auto st = rollback_journal(j, {}, original);
  CHECK(st);
  CHECK(std::filesystem::exists(original));
  CHECK(!std::filesystem::exists(assets));
  CHECK(!std::filesystem::exists(root / "RepackagerAssets"));
  std::filesystem::remove_all(root, ec);
}

TEST(package_query_matches_name_pfn_full_and_aumid) {
  const auto name = std::string_view("ZCode");
  const auto family = std::string_view("ZCode_mhb6sk8yz7b6a");
  const auto full = std::string_view("ZCode_1.0.0.0_x64__mhb6sk8yz7b6a");
  CHECK(package_query_matches("ZCode", name, family, full));
  CHECK(package_query_matches("ZCode_mhb6sk8yz7b6a", name, family, full));
  CHECK(package_query_matches("ZCode_1.0.0.0_x64__mhb6sk8yz7b6a", name, family, full));
  CHECK(package_query_matches("ZCode_mhb6sk8yz7b6a!ZCode", name, family, full));
  CHECK(package_query_matches("ZCode_mhb6sk8yz7b6a!probe", name, family, full));
  CHECK(!package_query_matches("Other_mhb6sk8yz7b6a!ZCode", name, family, full));
  CHECK(!package_query_matches("Contoso.WinWf2", name, family, full));
  CHECK(!package_query_matches("", name, family, full));
}

TEST(unregister_treats_not_installed_hresults_as_success) {
  CHECK(is_package_not_installed_status(static_cast<std::int32_t>(0x80073CF1), ""));
  CHECK(is_package_not_installed_status(static_cast<std::int32_t>(0x80073CFD), ""));
  CHECK(is_package_not_installed_status(static_cast<std::int32_t>(0x80073D19), ""));
  CHECK(is_package_not_installed_status(0, "Windows cannot remove X because it is not installed"));
  CHECK(is_package_not_installed_status(
      0, "Windows 无法删除 Contoso.Fixture_1.0.0.0_x64__mhb6sk8yz7b6a，因为当前用户未安装该程序包。"));
  CHECK(!is_package_not_installed_status(static_cast<std::int32_t>(0x80073D02), "packages in use"));
}

TEST(remove_retrofit_deletes_recorded_asset_dir) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-rm-assets";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto data = root / "data";
  const auto app = root / "app";
  std::filesystem::create_directories(app, ec);
  const char* prev_data = std::getenv("REPACKAGER_DATA_DIR");
  const std::string prev_data_s = prev_data ? prev_data : "";
#ifdef _WIN32
  _putenv_s("REPACKAGER_DATA_DIR", data.string().c_str());
#else
  setenv("REPACKAGER_DATA_DIR", data.string().c_str(), 1);
#endif
  {
    std::ofstream(app / "probe.exe") << "MZ";
  }
  OperationJournal journal;
  journal.operation_id = "rm-assets";
  auto assets = generate_assets(app / "RepackagerAssets" / "op1", {}, "Contoso.RmAssets", &journal);
  CHECK(assets);
  Receipt rec;
  rec.operation_id = "rm-assets";
  rec.command = "retrofit-win32-inplace";
  rec.identity.name = "Contoso.RmAssets";
  rec.output_root = app.string();
  rec.source.path = app.string();
  rec.created_paths = assets.value().created;
  rec.created_paths.push_back(CreatedPath{(app / "RepackagerAssets" / "op1").string(), {}});
  rec.created_paths.push_back(CreatedPath{(app / "RepackagerAssets").string(), {}});
  CHECK(write_authoritative_receipt(rec));
  const int code = run_cli(std::vector<std::string>{"remove-retrofit", "--name", "Contoso.RmAssets"});
  CHECK_EQ(code, 0);
  CHECK(std::filesystem::exists(app / "probe.exe"));
  CHECK(!std::filesystem::exists(app / "RepackagerAssets"));
#ifdef _WIN32
  _putenv_s("REPACKAGER_DATA_DIR", prev_data_s.c_str());
#else
  if (prev_data_s.empty()) unsetenv("REPACKAGER_DATA_DIR");
  else setenv("REPACKAGER_DATA_DIR", prev_data_s.c_str(), 1);
#endif
  std::filesystem::remove_all(root, ec);
}

#ifndef _WIN32
TEST(remove_retrofit_elevates_for_protected_directory) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-rm-elev";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  const auto data = root / "data";
  const auto app = root / "app";
  std::filesystem::create_directories(app, ec);
  const char* prev_data = std::getenv("REPACKAGER_DATA_DIR");
  const std::string prev_data_s = prev_data ? prev_data : "";
  setenv("REPACKAGER_DATA_DIR", data.string().c_str(), 1);
  Receipt rec;
  rec.operation_id = "rm-elev";
  rec.command = "retrofit-win32-inplace";
  rec.identity.name = "Contoso.RmElev";
  rec.output_root = app.string();
  rec.source.path = app.string();
  rec.created_paths.push_back(CreatedPath{(app / "AppxManifest.xml").string(), {}});
  CHECK(write_authoritative_receipt(rec));
  std::filesystem::permissions(app, std::filesystem::perms::owner_read |
                                        std::filesystem::perms::owner_exec,
                               std::filesystem::perm_options::replace, ec);
  const int code = run_cli(std::vector<std::string>{"remove-retrofit", "--name", "Contoso.RmElev"});
  std::filesystem::permissions(app, std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace, ec);
  // Linux has no ShellExecuteExW runas; the shipped elevate path returns Environment.
  CHECK(code == static_cast<int>(ExitCode::Environment) ||
        code == static_cast<int>(ExitCode::Elevation));
  if (prev_data_s.empty()) unsetenv("REPACKAGER_DATA_DIR");
  else setenv("REPACKAGER_DATA_DIR", prev_data_s.c_str(), 1);
  std::filesystem::remove_all(root, ec);
}
#endif

TEST(package_io_both_backends_inspect_zip_msix) {
  const auto root = std::filesystem::temp_directory_path() / "repackager-msix-io";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  std::filesystem::create_directories(root, ec);
  const auto pkg = root / "tiny.msix";
  ManifestRequest req;
  req.identity.name = "Contoso.Tiny";
  req.application.id = "App";
  req.application.executable = "app.exe";
  auto gen = generate_sparse_manifest(req);
  std::vector<ZipEntry> entries;
  ZipEntry man;
  man.name = "AppxManifest.xml";
  man.data.assign(gen.xml.begin(), gen.xml.end());
  entries.push_back(std::move(man));
  ZipEntry payload;
  payload.name = "app.exe";
  payload.data = {'M', 'Z'};
  entries.push_back(std::move(payload));
  CHECK(zip_write(pkg, entries));

  bool zip_seam_ok = false;
  for (auto backend : available_package_io_backends()) {
    auto io = create_package_io(backend);
    CHECK(io);
    auto info = io->inspect(pkg);
    if (!info) {
      // Windows in-box AppxPackaging rejects a STORE-only fixture (no block map).
      // The zip seam (Linux both backends; Windows msix_sdk when the SDK is not
      // linked) must still succeed so both I/O names stay exercisable.
      continue;
    }
    zip_seam_ok = true;
    CHECK_EQ(info.value().identity.name, std::string("Contoso.Tiny"));
    CHECK(!info.value().applications.empty());
    const auto dest = root / ("out-" + io->backend_name());
    auto ex = io->extract(pkg, dest);
    CHECK(ex);
    CHECK(std::filesystem::exists(dest / "AppxManifest.xml"));
  }
  CHECK(zip_seam_ok);
  std::filesystem::remove_all(root, ec);
}
