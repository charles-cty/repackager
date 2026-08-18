#include "pe_builder.hpp"
#include "repackager/hash.hpp"
#include "repackager/manifest.hpp"
#include "repackager/pe.hpp"
#include "test_support.hpp"

#include <filesystem>

using namespace repackager;

static std::filesystem::path tmp_pe(const char* name) {
  auto dir = std::filesystem::temp_directory_path() / "repackager-pe-tests";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  return dir / name;
}

TEST(pe_inspect_no_manifest_then_patch) {
  const auto path = tmp_pe("no-manifest.exe");
  CHECK(test::write_minimal_pe(path, test::PeBuildOptions{}));
  auto before = inspect_pe(path);
  CHECK(before);
  CHECK(before.value().is_pe);
  CHECK_EQ(before.value().architecture, Architecture::X64);
  CHECK(!before.value().has_embedded_manifest);
  CHECK(!before.value().authenticode_present);
  CHECK_EQ(before.value().authenticode_status, std::string("unsigned"));

  PatchExeOptions opt;
  opt.identity = MsixIdentityTuple{"Contoso.NoMan", std::string(kUnsignedPublisher), "App"};
  auto patched = patch_exe_identity(path, opt);
  CHECK(patched);
  CHECK(msix_tuple_matches(patched.value().verified, opt.identity));
  auto after = inspect_pe(path);
  CHECK(after.value().has_embedded_manifest);
  auto tup = extract_msix_tuple(after.value().embedded_manifest);
  CHECK(tup);
  CHECK(msix_tuple_matches(tup.value(), opt.identity));
}

TEST(pe_merge_preserves_complex_manifest) {
  const char* complex =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
      "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
      "  <assemblyIdentity version=\"1.2.3.4\" name=\"Contoso.Complex\" "
      "processorArchitecture=\"amd64\" type=\"win32\"/>\n"
      "  <dependency>\n"
      "    <dependentAssembly>\n"
      "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" "
      "version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" "
      "language=\"*\"/>\n"
      "    </dependentAssembly>\n"
      "  </dependency>\n"
      "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
      "    <security>\n"
      "      <requestedPrivileges>\n"
      "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>\n"
      "      </requestedPrivileges>\n"
      "    </security>\n"
      "  </trustInfo>\n"
      "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">\n"
      "    <application>\n"
      "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>\n"
      "    </application>\n"
      "  </compatibility>\n"
      "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
      "    <windowsSettings>\n"
      "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>\n"
      "    </windowsSettings>\n"
      "  </application>\n"
      "</assembly>\n";
  auto merged = patch_embedded_manifest_xml(complex, MsixIdentityTuple{"P", "CN=Pub", "A"});
  CHECK(merged);
  CHECK(merged.value().find("asInvoker") != std::string::npos);
  CHECK(merged.value().find("dpiAware") != std::string::npos);
  CHECK(merged.value().find("8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a") != std::string::npos);
  CHECK(merged.value().find("Microsoft.Windows.Common-Controls") != std::string::npos);
  CHECK(merged.value().find("Contoso.Complex") != std::string::npos);
  CHECK(merged.value().find("packageName=\"P\"") != std::string::npos);
  auto tup = extract_msix_tuple(merged.value());
  CHECK(tup);
  CHECK_EQ(tup.value().package_name, std::string("P"));

  const auto path = tmp_pe("complex.exe");
  test::PeBuildOptions b;
  b.manifest = complex;
  CHECK(test::write_minimal_pe(path, b));
  PatchExeOptions opt;
  opt.identity = MsixIdentityTuple{"P", "CN=Pub", "A"};
  auto patched = patch_exe_identity(path, opt);
  CHECK(patched);
  auto after = inspect_pe(path);
  CHECK(after.value().embedded_manifest.find("asInvoker") != std::string::npos);
  CHECK(after.value().embedded_manifest.find("dpiAware") != std::string::npos);
}

TEST(pe_mismatched_identity_after_patch_fails) {
  // Drive the shipped merge then assert that a different tuple does not match.
  auto xml = patch_embedded_manifest_xml("", MsixIdentityTuple{"Wanted", "CN=A", "App"});
  CHECK(xml);
  auto got = extract_msix_tuple(xml.value());
  CHECK(got);
  CHECK(!msix_tuple_matches(got.value(), MsixIdentityTuple{"Other", "CN=A", "App"}));
}

TEST(pe_signed_without_consent_refuses) {
  const auto path = tmp_pe("signed.exe");
  test::PeBuildOptions b;
  b.authenticode = true;
  CHECK(test::write_minimal_pe(path, b));
  auto info = inspect_pe(path);
  CHECK(info.value().authenticode_present);
  PatchExeOptions opt;
  opt.identity = MsixIdentityTuple{"N", "CN=P", "A"};
  opt.accept_signature_loss = false;
  auto r = patch_exe_identity(path, opt);
  CHECK(!r);
  CHECK(r.code() == ExitCode::SignatureConsent);
}

TEST(pe_signed_with_consent_proceeds) {
  const auto path = tmp_pe("signed-ok.exe");
  test::PeBuildOptions b;
  b.authenticode = true;
  CHECK(test::write_minimal_pe(path, b));
  PatchExeOptions opt;
  opt.identity = MsixIdentityTuple{"N", "CN=P", "A"};
  opt.accept_signature_loss = true;
  auto r = patch_exe_identity(path, opt);
  CHECK(r);
  CHECK(msix_tuple_matches(r.value().verified, opt.identity));
}

TEST(pe_empty_merge_creates_base) {
  auto xml = patch_embedded_manifest_xml("", MsixIdentityTuple{"N", "CN=P", "A"});
  CHECK(xml);
  CHECK(xml.value().find("<msix") != std::string::npos ||
        xml.value().find("msix") != std::string::npos);
}
