#pragma once

#include "repackager/error.hpp"
#include "repackager/manifest.hpp"
#include "repackager/models.hpp"
#include "repackager/xml.hpp"

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

struct CompatDecision {
  bool keep = true;
  std::string reason;
  std::string declaration;  // short label
};

using ManifestValidator = std::function<Status(std::string_view xml)>;

struct TransformResult {
  XmlDocument manifest;
  std::string xml;
  std::vector<Diagnostic> warnings;
  std::vector<std::string> kept;
  std::vector<std::string> dropped;
};

// Known-incompatible with sparse win32App/mediumIL (before MakeAppx).
bool sparse_incompatible_declaration(const XmlNode& node, std::string& reason);

// Build a fresh sparse base, then add source declarations one at a time.
// Each candidate is validated (MakeAppx /nv when provided). Valid properties,
// capabilities, dependencies, and extensions are kept; others are dropped
// with warnings.
Expected<TransformResult> transform_msix_manifest_to_sparse(
    const XmlDocument& source,
    const ManifestRequest& request,
    const ManifestValidator& validator = {});

}  // namespace repackager
