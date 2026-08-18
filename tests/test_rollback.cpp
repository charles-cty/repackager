#include "pe_builder.hpp"
#include "repackager/cli.hpp"
#include "repackager/hash.hpp"
#include "repackager/journal.hpp"
#include "repackager/manifest.hpp"
#include "repackager/package_io.hpp"
#include "repackager/paths.hpp"
#include "repackager/stage.hpp"
#include "repackager/zip.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <fstream>

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
