#include "repackager/compat.hpp"
#include "repackager/manifest.hpp"
#include "repackager/xml.hpp"
#include "test_support.hpp"

#include <string>

using namespace repackager;

TEST(compat_drops_incompatible_and_keeps_valid) {
  const char* source =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\" "
      "xmlns:rescap=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities\">\n"
      "  <Identity Name=\"Old.Name\" Publisher=\"CN=Old\" Version=\"1.0.0.0\" ProcessorArchitecture=\"x64\"/>\n"
      "  <Properties><DisplayName>Old</DisplayName><Description>KeepMe</Description></Properties>\n"
      "  <Capabilities>\n"
      "    <Capability Name=\"internetClient\"/>\n"
      "    <rescap:Capability Name=\"runFullTrust\"/>\n"
      "  </Capabilities>\n"
      "  <Applications>\n"
      "    <Application Id=\"App\" Executable=\"app.exe\" TrustLevel=\"appContainer\">\n"
      "      <Extensions>\n"
      "        <Extension Category=\"windows.fileTypeAssociation\"/>\n"
      "        <Extension Category=\"windows.inProcessServer\"/>\n"
      "      </Extensions>\n"
      "    </Application>\n"
      "  </Applications>\n"
      "</Package>\n";
  auto doc = parse_xml(source);
  CHECK(doc);
  ManifestRequest req;
  req.identity.name = "New.Name";
  req.identity.publisher = std::string(kUnsignedPublisher);
  req.application.id = "App";
  req.application.executable = "app.exe";
  int validated = 0;
  auto tr = transform_msix_manifest_to_sparse(doc.value(), req, [&](std::string_view xml) {
    ++validated;
    CHECK(std::string(xml).find("New.Name") != std::string::npos);
    return Status::success();
  });
  CHECK(tr);
  CHECK(validated > 0);
  const auto xml = tr.value().xml;
  CHECK(xml.find("New.Name") != std::string::npos);
  CHECK(xml.find("win32App") != std::string::npos);
  CHECK(xml.find("KeepMe") != std::string::npos);
  CHECK(xml.find("internetClient") != std::string::npos);
  CHECK(xml.find("windows.fileTypeAssociation") != std::string::npos);
  bool dropped_ips = false;
  for (const auto& d : tr.value().dropped) {
    if (d.find("inProcessServer") != std::string::npos) dropped_ips = true;
  }
  CHECK(dropped_ips);
}

TEST(compat_multi_app_uses_source_application_id) {
  const char* source =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\" "
      "xmlns:uap=\"http://schemas.microsoft.com/appx/manifest/uap/windows10\">\n"
      "  <Applications>\n"
      "    <Application Id=\"First\" Executable=\"first.exe\">\n"
      "      <Extensions>\n"
      "        <uap:Extension Category=\"windows.fileTypeAssociation\">\n"
      "          <uap:FileTypeAssociation Name=\"firsttype\"/>\n"
      "        </uap:Extension>\n"
      "      </Extensions>\n"
      "    </Application>\n"
      "    <Application Id=\"Second\" Executable=\"second.exe\">\n"
      "      <Extensions>\n"
      "        <uap:Extension Category=\"windows.protocol\">\n"
      "          <uap:Protocol Name=\"secondproto\"/>\n"
      "        </uap:Extension>\n"
      "      </Extensions>\n"
      "    </Application>\n"
      "  </Applications>\n"
      "</Package>\n";
  auto doc = parse_xml(source);
  CHECK(doc);
  ManifestRequest req;
  req.identity.name = "New.Name";
  req.application.id = "ConvertedApp";
  req.application.executable = "second.exe";
  req.source_application_id = "Second";
  auto tr = transform_msix_manifest_to_sparse(doc.value(), req, {});
  CHECK(tr);
  const auto xml = tr.value().xml;
  CHECK(xml.find("secondproto") != std::string::npos);
  CHECK(xml.find("firsttype") == std::string::npos);
  CHECK(xml.find("ConvertedApp") != std::string::npos);
}

TEST(compat_validator_can_drop_failing_candidate) {
  const char* source =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\">\n"
      "  <Capabilities><Capability Name=\"privateNetworkClientServer\"/></Capabilities>\n"
      "</Package>\n";
  auto doc = parse_xml(source);
  CHECK(doc);
  ManifestRequest req;
  req.identity.name = "N";
  req.application.id = "A";
  req.application.executable = "a.exe";
  auto tr = transform_msix_manifest_to_sparse(doc.value(), req, [](std::string_view xml) {
    if (std::string(xml).find("privateNetworkClientServer") != std::string::npos) {
      return Status::fail(ExitCode::Validation, "MakeAppx /nv rejected capability");
    }
    return Status::success();
  });
  CHECK(tr);
  CHECK(tr.value().xml.find("privateNetworkClientServer") == std::string::npos);
  CHECK(!tr.value().dropped.empty());
}
