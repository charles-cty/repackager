#include "repackager/manifest.hpp"
#include "repackager/xml.hpp"
#include "test_support.hpp"

using namespace repackager;

TEST(xml_escape_and_namespaces) {
  CHECK_EQ(xml_escape("a<b>&c>"), std::string("a&lt;b&gt;&amp;c&gt;"));
  CHECK_EQ(xml_escape_attr("say \"hi\""), std::string("say &quot;hi&quot;"));
  CHECK_EQ(std::string(prefix_for_namespace(kNsUap10)), std::string("uap10"));
  CHECK_EQ(local_name("uap10:TrustLevel"), std::string("TrustLevel"));
}

TEST(xml_parse_roundtrip_appx_fragment) {
  const char* src =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\" "
      "xmlns:uap10=\"http://schemas.microsoft.com/appx/manifest/uap/windows10/10\">\n"
      "  <Identity Name=\"N\" Publisher=\"CN=X\" Version=\"1.0.0.0\"/>\n"
      "  <Properties>\n"
      "    <DisplayName>A &amp; B</DisplayName>\n"
      "  </Properties>\n"
      "</Package>\n";
  auto doc = parse_xml(src);
  CHECK(doc);
  CHECK_EQ(doc.value().root.name, std::string("Package"));
  CHECK_EQ(doc.value().root.find_child("Identity")->attr("Name"), std::string("N"));
  CHECK_EQ(doc.value().root.find_child("Properties")->find_child("DisplayName")->text,
           std::string("A & B"));
  const auto out = serialize_xml(doc.value(), true);
  CHECK(out.find("&amp;") != std::string::npos);
  CHECK(out.find("xmlns") != std::string::npos);
  auto again = parse_xml(out);
  CHECK(again);
  CHECK_EQ(again.value().root.find_child("Identity")->attr("Name"), std::string("N"));
}

TEST(xml_sparse_manifest_contains_required_tokens) {
  ManifestRequest req;
  req.identity.name = "Contoso.Probe";
  req.identity.publisher = std::string(kUnsignedPublisher);
  req.application.id = "Probe";
  req.application.executable = "probe.exe";
  req.application.display_name = "Probe";
  auto gen = generate_sparse_manifest(req);
  CHECK(gen.xml.find("win32App") != std::string::npos);
  CHECK(gen.xml.find("mediumIL") != std::string::npos);
  CHECK(gen.xml.find("AllowExternalContent") != std::string::npos);
  CHECK(gen.xml.find("Contoso.Probe") != std::string::npos);
  CHECK(gen.xml.find(std::string(kUnsignedPublisherOid)) != std::string::npos);
  CHECK(gen.xml.find("ProcessorArchitecture=\"neutral\"") != std::string::npos);
}

TEST(xml_loose_manifest_packaged_classic) {
  ManifestRequest req;
  req.layout = LayoutKind::LooseFull;
  req.identity.name = "Contoso.Loose";
  req.identity.architecture = Architecture::X64;
  req.application.id = "App";
  req.application.executable = "app.exe";
  auto gen = generate_loose_manifest(req);
  CHECK(gen.xml.find("packagedClassicApp") != std::string::npos);
  CHECK(gen.xml.find("mediumIL") != std::string::npos);
  CHECK(gen.xml.find("runFullTrust") != std::string::npos);
  CHECK(gen.xml.find("AllowExternalContent") == std::string::npos);
  CHECK(gen.xml.find("x64") != std::string::npos);
  CHECK(gen.xml.find("EntryPoint=\"Windows.FullTrustApplication\"") != std::string::npos);
  CHECK(gen.xml.find("Executable=\"app.exe\"") != std::string::npos);
  CHECK(gen.xml.find("Executable=\"C:") == std::string::npos);

  req.application.trust = TrustLevel::AppContainer;
  auto ac = generate_loose_manifest(req);
  CHECK(ac.xml.find("appContainer") != std::string::npos);
  CHECK(ac.xml.find("runFullTrust") == std::string::npos);
  CHECK(ac.xml.find("EntryPoint=\"Windows.PartialTrustApplication\"") != std::string::npos);
}

TEST(xml_sparse_manifest_omits_entrypoint) {
  ManifestRequest req;
  req.identity.name = "Contoso.Probe";
  req.application.id = "Probe";
  req.application.executable = "probe.exe";
  auto gen = generate_sparse_manifest(req);
  CHECK(gen.xml.find("EntryPoint") == std::string::npos);
  CHECK(gen.xml.find("win32App") != std::string::npos);
}
