#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"
#include "repackager/xml.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace repackager {

struct ManifestRequest {
  PackageIdentity identity;
  ApplicationDeclaration application;
  LayoutKind layout = LayoutKind::SparseExternal;
  std::string logo{"Assets\\StoreLogo.png"};
  std::string square44{"Assets\\Square44x44Logo.png"};
  std::string square150{"Assets\\Square150x150Logo.png"};
  std::string publisher_display_name{"Repackager"};
  bool allow_external_content = true;
  bool run_full_trust = true;
  bool unvirtualized_resources = true;
  // When transforming an installed MSIX, match this source Application/@Id
  // (not the new package application.id) for extension copy.
  // Brace-init is required: MSVC's implicit default ctor skips a trailing
  // class member that has no default member initializer.
  std::string source_application_id{};
};

struct GeneratedManifest {
  XmlDocument document;
  std::string xml;
};

GeneratedManifest generate_sparse_manifest(const ManifestRequest& request);
GeneratedManifest generate_loose_manifest(const ManifestRequest& request);
GeneratedManifest generate_manifest(const ManifestRequest& request);

// Embedded EXE fusion manifest: insert/update <msix> while preserving UAC,
// DPI, compatibility, dependencies, and assembly identity.
struct MsixIdentityTuple {
  std::string package_name;
  std::string publisher;
  std::string application_id;
};

Expected<std::string> merge_msix_element(std::string_view existing_manifest_xml,
                                         const MsixIdentityTuple& tuple);

Expected<MsixIdentityTuple> extract_msix_tuple(std::string_view manifest_xml);

std::string create_base_exe_manifest(const MsixIdentityTuple& tuple,
                                     std::string_view assembly_name = "Application");

bool msix_tuple_matches(const MsixIdentityTuple& a, const MsixIdentityTuple& b);

}  // namespace repackager
