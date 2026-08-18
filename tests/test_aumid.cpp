#include "repackager/aumid.hpp"
#include "repackager/identity.hpp"
#include "test_support.hpp"

using namespace repackager;

TEST(aumid_is_family_bang_application) {
  PackageIdentity id;
  id.name = "Contoso.App";
  id.publisher =
      "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
  const auto family = package_family_name(id);
  const auto aumid = construct_aumid(family, "Main");
  CHECK_EQ(aumid, family + "!Main");
  CHECK(aumid.find('!') != std::string::npos);
  CHECK_EQ(aumid, std::string("Contoso.App_8wekyb3d8bbwe!Main"));
}
