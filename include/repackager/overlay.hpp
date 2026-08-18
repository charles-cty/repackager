#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"
#include "repackager/xml.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace repackager {

inline constexpr std::string_view kReservedOverlayFields[] = {
    "Identity",
    "Name",
    "Publisher",
    "Version",
    "ProcessorArchitecture",
    "ResourceId",
    "Executable",
    "Id",
    "RuntimeBehavior",
    "TrustLevel",
    "AllowExternalContent",
    "EntryPoint",
};

struct OverlayConflict {
  std::string field;
  std::string message;
};

struct OverlayResult {
  XmlDocument manifest;
  std::vector<Diagnostic> warnings;
};

bool is_reserved_overlay_field(std::string_view name);

// Strict merge: reserved identity/runtime/trust/external-content settings
// cannot be overridden. Invalid overlays fail; nothing is dropped silently.
Expected<OverlayResult> apply_manifest_overlay(const XmlDocument& base,
                                               const XmlDocument& overlay);

Expected<OverlayResult> apply_manifest_overlay_text(std::string_view base_xml,
                                                    std::string_view overlay_xml);

}  // namespace repackager
