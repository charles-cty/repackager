#include "pe_builder.hpp"
#include "repackager/cli.hpp"
#include "repackager/hash.hpp"
#include "repackager/receipt.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <fstream>

using namespace repackager;

TEST(cli_accepts_named_commands) {
  const char* names[] = {
      "list-win32",
      "list-msix",
      "inspect-msix",
      "extract-msix",
      "stage-files",
      "inspect-exe",
      "patch-exe-identity",
      "make-manifest",
      "transform-msix-manifest",
      "apply-manifest-overlay",
      "register-sparse",
      "register-loose",
      "activate",
      "status",
      "unregister",
      "remove-retrofit",
      "retrofit-win32-sparse",
      "retrofit-win32-inplace",
      "retrofit-msix-sparse",
  };
  for (const char* n : names) {
    auto c = command_from_name(n);
    CHECK(c.has_value());
    auto parsed = parse_command(std::vector<std::string>{n, "--help"});
    CHECK(parsed);
    CHECK(parsed.value().help);
    CHECK_EQ(std::string(command_name(*c)), std::string(n));
  }
}

TEST(cli_rejects_unknown_and_missing) {
  auto missing = parse_command(std::vector<std::string>{});
  CHECK(!missing);
  CHECK(missing.code() == ExitCode::Usage);

  auto unknown = parse_command(std::vector<std::string>{"not-a-command"});
  CHECK(!unknown);
  CHECK(unknown.code() == ExitCode::Usage);
}

TEST(cli_parse_options_and_flags) {
  auto p = parse_command(std::vector<std::string>{
      "retrofit-win32-sparse", "--source", "C:\\src", "--executable", "app.exe",
      "--output", "C:\\out", "--name", "Contoso.App", "--prepare-only",
      "--accept-signature-loss"});
  CHECK(p);
  CHECK(p.value().command == Command::RetrofitWin32Sparse);
  CHECK_EQ(p.value().require("source"), std::string("C:\\src"));
  CHECK_EQ(p.value().require("name"), std::string("Contoso.App"));
  CHECK(p.value().has_flag("prepare-only"));
  CHECK(p.value().has_flag("accept-signature-loss"));
}

TEST(cli_run_rejects_bad_usage_with_stable_exit) {
  const int code = run_cli(std::vector<std::string>{"make-manifest"});
  CHECK_EQ(code, static_cast<int>(ExitCode::Usage));
}

TEST(cli_make_manifest_writes_report_and_human_output) {
  const auto tmp = std::filesystem::temp_directory_path() / "repackager-cli-make";
  std::error_code ec;
  std::filesystem::remove_all(tmp, ec);
  std::filesystem::create_directories(tmp, ec);
  const auto out = tmp / "AppxManifest.xml";
  const auto report = tmp / "report.txt";
  const int code = run_cli(std::vector<std::string>{
      "make-manifest", "--layout", "sparse_external", "--name", "Contoso.Cli",
      "--executable", "app.exe", "--output", out.string(), "--report", report.string()});
  CHECK_EQ(code, 0);
  CHECK(std::filesystem::exists(out));
  CHECK(std::filesystem::exists(report));
  std::ifstream in(out);
  std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  CHECK(xml.find("win32App") != std::string::npos);
  CHECK(xml.find("Contoso.Cli") != std::string::npos);
  std::ifstream rin(report);
  std::string rt((std::istreambuf_iterator<char>(rin)), std::istreambuf_iterator<char>());
  CHECK(rt.find("make-manifest") != std::string::npos);
  const int abs = run_cli(std::vector<std::string>{
      "make-manifest", "--layout", "loose_full", "--name", "Contoso.Cli",
      "--executable", R"(C:\Program Files\ZCode\ZCode.exe)", "--output", out.string()});
  CHECK_EQ(abs, static_cast<int>(ExitCode::Validation));
  std::filesystem::remove_all(tmp, ec);
}

TEST(cli_transform_msix_manifest_uses_source_application_id) {
  const auto tmp = std::filesystem::temp_directory_path() / "repackager-cli-xform";
  std::error_code ec;
  std::filesystem::remove_all(tmp, ec);
  std::filesystem::create_directories(tmp, ec);
  const auto src = tmp / "source.xml";
  {
    std::ofstream out(src);
    out << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
           "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\" "
           "xmlns:uap=\"http://schemas.microsoft.com/appx/manifest/uap/windows10\">\n"
           "  <Applications>\n"
           "    <Application Id=\"First\" Executable=\"first.exe\">\n"
           "      <Extensions><uap:Extension Category=\"windows.fileTypeAssociation\">"
           "<uap:FileTypeAssociation Name=\"firsttype\"/></uap:Extension></Extensions>\n"
           "    </Application>\n"
           "    <Application Id=\"Second\" Executable=\"second.exe\">\n"
           "      <Extensions><uap:Extension Category=\"windows.protocol\">"
           "<uap:Protocol Name=\"secondproto\"/></uap:Extension></Extensions>\n"
           "    </Application>\n"
           "  </Applications>\n"
           "</Package>\n";
  }
  const auto dest = tmp / "out.xml";
  const int code = run_cli(std::vector<std::string>{
      "transform-msix-manifest", "--source", src.string(), "--name", "Contoso.Xform",
      "--executable", "second.exe", "--application-id", "ConvertedApp",
      "--source-application-id", "Second", "--output", dest.string()});
  CHECK_EQ(code, 0);
  std::ifstream in(dest);
  std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  CHECK(xml.find("secondproto") != std::string::npos);
  CHECK(xml.find("firsttype") == std::string::npos);
  CHECK(xml.find("ConvertedApp") != std::string::npos);
  std::filesystem::remove_all(tmp, ec);
}

TEST(cli_retrofit_win32_sparse_prepare_only_twice) {
  const auto tmp = std::filesystem::temp_directory_path() / "repackager-prepare-only";
  std::error_code ec;
  std::filesystem::remove_all(tmp, ec);
  const auto src = tmp / "src";
  std::filesystem::create_directories(src, ec);
  CHECK(test::write_minimal_pe(src / "probe.exe", test::PeBuildOptions{}));
  const auto source_hash = sha256_file_hex(src / "probe.exe");
  for (int i = 0; i < 2; ++i) {
    const auto out = tmp / ("out-" + std::to_string(i));
    const auto report = tmp / ("report-" + std::to_string(i) + ".txt");
    const int code = run_cli(std::vector<std::string>{
        "retrofit-win32-sparse", "--source", src.string(), "--executable", "probe.exe",
        "--output", out.string(), "--name", "Contoso.Prepare", "--prepare-only",
        "--report", report.string()});
    CHECK_EQ(code, 0);
    CHECK(std::filesystem::exists(out / "payload" / "probe.exe"));
    CHECK(std::filesystem::exists(out / "identity" / "AppxManifest.xml"));
    CHECK(std::filesystem::exists(out / ".repackager" / "receipt.json"));
    std::ifstream in(out / "identity" / "AppxManifest.xml");
    std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(xml.find("win32App") != std::string::npos);
    CHECK(xml.find("mediumIL") != std::string::npos);
    CHECK(xml.find("AllowExternalContent") != std::string::npos);
    CHECK(xml.find("Contoso.Prepare") != std::string::npos);
    CHECK(xml.find("OID.2.25.311729368913984317654407730594956997722=1") != std::string::npos);
    CHECK_EQ(sha256_file_hex(src / "probe.exe"), source_hash);
    auto rec = read_receipt_file(out / ".repackager" / "receipt.json");
    CHECK(rec);
    CHECK(!rec.value().created_paths.empty());
    CHECK(!rec.value().created_paths.front().path.empty());
  }
  const int inspect = run_cli(std::vector<std::string>{
      "inspect-exe", "--input", (src / "probe.exe").string(), "--report",
      (tmp / "inspect.txt").string()});
  CHECK_EQ(inspect, 0);
  CHECK(std::filesystem::exists(tmp / "inspect.txt"));
  std::filesystem::remove_all(tmp, ec);
}
