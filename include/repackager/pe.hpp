#pragma once

#include "repackager/error.hpp"
#include "repackager/manifest.hpp"
#include "repackager/models.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace repackager {

struct PeInspection {
  Architecture architecture = Architecture::Neutral;
  bool is_pe = false;
  bool is_dll = false;
  bool has_embedded_manifest = false;
  std::string embedded_manifest;
  std::string file_version;
  std::string product_name;
  std::string file_description;
  std::string sha256;
  bool authenticode_present = false;
  std::string authenticode_status;  // unsigned | present | trusted | untrusted
};

Expected<PeInspection> inspect_pe(const std::filesystem::path& path);

struct PatchExeOptions {
  MsixIdentityTuple identity;
  bool accept_signature_loss = false;
  std::filesystem::path mt_exe;
};

struct PatchExeResult {
  std::string written_manifest;
  MsixIdentityTuple verified;
  bool signature_stripped = false;
};

// Extract or create a base manifest, insert <msix>, re-embed, re-extract,
// and verify the identity tuple. Signed staged copies require consent.
Expected<PatchExeResult> patch_exe_identity(const std::filesystem::path& staged_exe,
                                            const PatchExeOptions& options);

// Portable XML merge used by both mt.exe and tests.
Expected<std::string> patch_embedded_manifest_xml(std::string_view existing_or_empty,
                                                  const MsixIdentityTuple& tuple);

}  // namespace repackager
