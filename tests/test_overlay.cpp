#include "repackager/manifest.hpp"
#include "repackager/overlay.hpp"
#include "test_support.hpp"

using namespace repackager;

static std::string base_sparse() {
  ManifestRequest req;
  req.identity.name = "Contoso.Base";
  req.application.id = "App";
  req.application.executable = "app.exe";
  req.application.display_name = "Base";
  return generate_sparse_manifest(req).xml;
}

TEST(overlay_reserved_fields_fail) {
  CHECK(is_reserved_overlay_field("Identity"));
  CHECK(is_reserved_overlay_field("TrustLevel"));
  CHECK(is_reserved_overlay_field("AllowExternalContent"));
  CHECK(!is_reserved_overlay_field("PublisherDisplayName"));

  const auto base = base_sparse();
  const char* bad_identity =
      "<Overlay><Identity Name=\"Hijack\" Publisher=\"CN=Evil\" Version=\"9.9.9.9\"/></Overlay>";
  auto r = apply_manifest_overlay_text(base, bad_identity);
  CHECK(!r);
  CHECK(r.code() == ExitCode::Conflict);

  const char* bad_trust =
      "<Overlay><Application TrustLevel=\"appContainer\"/></Overlay>";
  auto r2 = apply_manifest_overlay_text(base, bad_trust);
  CHECK(!r2);
  CHECK(r2.code() == ExitCode::Conflict);

  const char* bad_aec =
      "<Overlay><Properties><AllowExternalContent>false</AllowExternalContent></Properties></Overlay>";
  auto r3 = apply_manifest_overlay_text(base, bad_aec);
  CHECK(!r3);
}

TEST(overlay_invalid_xml_fails) {
  auto r = apply_manifest_overlay_text(base_sparse(), "<Overlay><Nope>");
  CHECK(!r);
  CHECK(r.code() == ExitCode::Validation);
}

TEST(overlay_merges_capabilities_and_properties) {
  const char* ov =
      "<?xml version=\"1.0\"?>\n"
      "<Overlay>\n"
      "  <Properties><PublisherDisplayName>Contoso</PublisherDisplayName></Properties>\n"
      "  <Capabilities><Capability Name=\"internetClient\"/></Capabilities>\n"
      "</Overlay>\n";
  auto r = apply_manifest_overlay_text(base_sparse(), ov);
  CHECK(r);
  const auto xml = serialize_xml(r.value().manifest, true);
  CHECK(xml.find("Contoso") != std::string::npos);
  CHECK(xml.find("internetClient") != std::string::npos);
  CHECK(xml.find("win32App") != std::string::npos);
  CHECK(xml.find("Contoso.Base") != std::string::npos);
}
