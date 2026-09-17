#include "repackager/toolchain.hpp"
#include "test_support.hpp"

using namespace repackager;

TEST(toolchain_normalizes_sha1_thumbprint) {
  auto normalized = normalize_sha1_thumbprint("00 112233445566778899aabbccddeeff00112233\n");
  CHECK(normalized);
  CHECK_EQ(normalized.value(), std::string("00112233445566778899AABBCCDDEEFF00112233"));
}

TEST(toolchain_rejects_non_sha1_thumbprints) {
  CHECK(!normalize_sha1_thumbprint("00112233"));
  CHECK(!normalize_sha1_thumbprint("00112233445566778899AABBCCDDEEFF001122334"));
  CHECK(!normalize_sha1_thumbprint("00112233445566778899AABBCCDDEEFF0011223G"));
}
