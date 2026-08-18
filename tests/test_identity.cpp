#include "repackager/hash.hpp"
#include "repackager/identity.hpp"
#include "repackager/manifest.hpp"
#include "test_support.hpp"

using namespace repackager;

TEST(default_ctor_constructs_trailing_string_members) {
  // MSVC's implicit default ctor used to skip class members that follow the
  // last default-member-initializer (0xCC dest, AV on assign).
  ManifestRequest req;
  req.source_application_id = "Second";
  CHECK_EQ(req.source_application_id, std::string("Second"));
  PackageIdentity ident;
  ident.resource_id = "res";
  CHECK_EQ(ident.resource_id, std::string("res"));
  ApplicationDeclaration app;
  app.display_name = "Disp";
  app.description = "Desc";
  CHECK_EQ(app.display_name, std::string("Disp"));
  CHECK_EQ(app.description, std::string("Desc"));
}

TEST(identity_valid_and_invalid_name) {
  CHECK(validate_package_name("Contoso.App"));
  CHECK(validate_package_name("Abc"));
  CHECK(!validate_package_name("ab"));
  CHECK(!validate_package_name(".StartsBad"));
  CHECK(!validate_package_name("EndsBad."));
  CHECK(!validate_package_name("has space"));
  CHECK(!validate_package_name("bad_underscore"));
}

TEST(identity_valid_and_invalid_publisher_and_version) {
  CHECK(validate_publisher(kUnsignedPublisher));
  CHECK(!validate_publisher("not-a-publisher"));
  CHECK(validate_version("1.0.0.0"));
  CHECK(validate_version("10.20.30.40"));
  CHECK(!validate_version("1.0.0"));
  CHECK(!validate_version("1.0.0.65536"));
  CHECK(!validate_version("1.0.0.x"));
}

TEST(identity_application_id_and_sanitize) {
  CHECK(validate_application_id("MyApp"));
  CHECK(!validate_application_id("1bad"));
  CHECK(!validate_application_id("has space"));
  const auto id = sanitize_application_id("hello world.exe");
  CHECK(validate_application_id(id));
  CHECK(id.find(' ') == std::string::npos);
}

TEST(identity_publisher_id_known_vector) {
  // Microsoft Photos / Calculator publisher id.
  const char* pub =
      "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
  CHECK_EQ(publisher_id(pub), std::string("8wekyb3d8bbwe"));
}

TEST(identity_full_and_family_name) {
  PackageIdentity id;
  id.name = "Contoso.App";
  id.publisher =
      "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
  id.version = "1.2.3.4";
  id.architecture = Architecture::Neutral;
  CHECK_EQ(package_family_name(id), std::string("Contoso.App_8wekyb3d8bbwe"));
  CHECK_EQ(package_full_name(id), std::string("Contoso.App_1.2.3.4_neutral__8wekyb3d8bbwe"));
}

TEST(sha256_abc_vector) {
  CHECK_EQ(to_hex(sha256_string("abc")),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}
