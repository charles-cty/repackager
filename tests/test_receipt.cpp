#include "repackager/identity.hpp"
#include "repackager/receipt.hpp"
#include "test_support.hpp"

using namespace repackager;

TEST(receipt_json_roundtrip_required_fields) {
  Receipt r;
  r.schema_version = 1;
  r.operation_id = "op-1";
  r.command = "retrofit-win32-sparse";
  r.identity.name = "Contoso.App";
  r.identity.publisher = std::string(kUnsignedPublisher);
  r.identity.version = "1.2.3.4";
  r.identity.architecture = Architecture::Neutral;
  r.layout = LayoutKind::SparseExternal;
  r.trust = TrustLevel::MediumIL;
  r.package_full_name = package_full_name(r.identity);
  r.package_family_name = package_family_name(r.identity);
  r.application_id = "App";
  r.aumid = make_aumid(r.package_family_name, r.application_id);
  r.created_paths.push_back(CreatedPath{"C:\\out\\payload\\app.exe", "abc"});
  r.warnings.push_back(Diagnostic{Diagnostic::Severity::Warning, "w1", "hello"});
  r.elevated = true;
  r.rollback_status = "none";
  r.source.kind = "win32-dir";
  r.source.path = "C:\\src";
  r.launch_result = "ok";

  const auto text = serialize_receipt(r);
  auto back = parse_receipt(text);
  CHECK(back);
  CHECK_EQ(back.value().schema_version, 1);
  CHECK_EQ(back.value().operation_id, std::string("op-1"));
  CHECK_EQ(back.value().command, std::string("retrofit-win32-sparse"));
  CHECK_EQ(back.value().identity.name, std::string("Contoso.App"));
  CHECK_EQ(back.value().identity.publisher, std::string(kUnsignedPublisher));
  CHECK_EQ(back.value().package_family_name, r.package_family_name);
  CHECK_EQ(back.value().aumid, r.aumid);
  CHECK_EQ(back.value().created_paths.size(), static_cast<std::size_t>(1));
  CHECK_EQ(back.value().created_paths[0].sha256, std::string("abc"));
  CHECK_EQ(back.value().warnings.size(), static_cast<std::size_t>(1));
  CHECK(back.value().elevated);
  CHECK_EQ(back.value().rollback_status, std::string("none"));
  CHECK_EQ(back.value().source.kind, std::string("win32-dir"));
}
