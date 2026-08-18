#include "repackager/overlay.hpp"

#include <algorithm>
#include <set>

namespace repackager {
namespace {

const std::set<std::string> kReservedNames = {
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

bool name_is_reserved(std::string_view name) {
  return kReservedNames.count(std::string(name)) != 0;
}

bool application_attr_reserved(std::string_view name) {
  return name == "Executable" || name == "RuntimeBehavior" || name == "TrustLevel" ||
         name == "EntryPoint" || name == "Name" || name == "Publisher" || name == "Version" ||
         name == "ProcessorArchitecture" || name == "ResourceId" ||
         name == "AllowExternalContent";
}

Status scan_reserved(const XmlNode& node, const char* where) {
  if (node.name == "Identity" || node.name == "AllowExternalContent") {
    return Status::fail(ExitCode::Conflict,
                        std::string(where) + " overlays reserved field '" + node.name + "'");
  }
  if (node.name == "Application" || node.name == "VisualElements") {
    for (const auto& a : node.attributes) {
      if (application_attr_reserved(a.name) && a.name != "Id") {
        return Status::fail(ExitCode::Conflict, std::string(where) +
                                                    " overlays reserved attribute '" + a.name +
                                                    "'");
      }
    }
  }
  for (const auto& c : node.children) {
    if (auto s = scan_reserved(c, where); !s) return s;
  }
  return Status::success();
}

XmlNode* ensure_child(XmlNode& parent, std::string name, std::string ns = {},
                      std::string prefix = {}) {
  if (auto* existing = parent.find_child(name)) return existing;
  XmlNode n;
  n.name = std::move(name);
  n.ns = std::move(ns);
  n.prefix = std::move(prefix);
  parent.children.push_back(std::move(n));
  return &parent.children.back();
}

bool same_capability(const XmlNode& a, const XmlNode& b) {
  return a.name == b.name && a.attr("Name") == b.attr("Name") && a.ns == b.ns;
}

bool same_extension(const XmlNode& a, const XmlNode& b) {
  if (a.name != b.name) return false;
  const auto ca = a.attr("Category");
  const auto cb = b.attr("Category");
  if (!ca.empty() || !cb.empty()) return ca == cb;
  return serialize_xml(XmlDocument{a}, false) == serialize_xml(XmlDocument{b}, false);
}

void merge_children_unique(XmlNode& dest, const std::vector<XmlNode>& incoming,
                           bool (*same)(const XmlNode&, const XmlNode&),
                           std::vector<Diagnostic>& warnings, std::string_view kind) {
  for (const auto& item : incoming) {
    bool found = false;
    for (const auto& existing : dest.children) {
      if (same(existing, item)) {
        found = true;
        warnings.push_back(Diagnostic{Diagnostic::Severity::Info, "overlay-duplicate",
                                      "overlay " + std::string(kind) +
                                          " already present; leaving existing"});
        break;
      }
    }
    if (!found) dest.children.push_back(item);
  }
}

const XmlNode* overlay_section(const XmlNode& root, std::string_view name) {
  if (root.name == name) return &root;
  return root.find_child(name);
}

Status merge_properties(XmlNode& dest_pkg, const XmlNode& overlay_props,
                        std::vector<Diagnostic>&) {
  auto* dest = ensure_child(dest_pkg, "Properties", std::string(kNsFoundation));
  for (const auto& child : overlay_props.children) {
    if (child.name == "AllowExternalContent" || child.name == "Identity") {
      return Status::fail(ExitCode::Conflict,
                          "overlay Properties may not set reserved field '" + child.name +
                              "'");
    }
    if (auto* existing = dest->find_child(child.name)) {
      *existing = child;
    } else {
      dest->children.push_back(child);
    }
  }
  for (const auto& a : overlay_props.attributes) {
    if (application_attr_reserved(a.name)) {
      return Status::fail(ExitCode::Conflict,
                          "overlay Properties reserved attribute '" + a.name + "'");
    }
  }
  return Status::success();
}

}  // namespace

bool is_reserved_overlay_field(std::string_view name) { return name_is_reserved(name); }

Expected<OverlayResult> apply_manifest_overlay(const XmlDocument& base,
                                               const XmlDocument& overlay) {
  OverlayResult result;
  result.manifest = base;
  XmlNode& pkg = result.manifest.root;
  if (pkg.name != "Package") {
    return Expected<OverlayResult>::fail(ExitCode::Validation,
                                         "base manifest root must be Package");
  }

  const XmlNode* src = &overlay.root;
  // Accept <Overlay>, <Package>, or a bare section.
  if (src->name == "Overlay" || src->name == "Package") {
    if (auto s = scan_reserved(*src, "overlay"); !s) {
      return Expected<OverlayResult>::fail(s.code, s.message);
    }
    if (src->name == "Package") {
      if (src->find_child("Identity")) {
        return Expected<OverlayResult>::fail(
            ExitCode::Conflict, "overlay must not include Identity (reserved)");
      }
    }
  } else {
    if (auto s = scan_reserved(*src, "overlay"); !s) {
      return Expected<OverlayResult>::fail(s.code, s.message);
    }
  }

  if (const auto* props = overlay_section(*src, "Properties")) {
    if (auto s = merge_properties(pkg, *props, result.warnings); !s) {
      return Expected<OverlayResult>::fail(s.code, s.message);
    }
  }

  if (const auto* caps = overlay_section(*src, "Capabilities")) {
    auto* dest = ensure_child(pkg, "Capabilities", std::string(kNsFoundation));
    merge_children_unique(*dest, caps->children, same_capability, result.warnings,
                          "capability");
  }

  if (const auto* deps = overlay_section(*src, "Dependencies")) {
    auto* dest = ensure_child(pkg, "Dependencies", std::string(kNsFoundation));
    merge_children_unique(
        *dest, deps->children,
        [](const XmlNode& a, const XmlNode& b) {
          return a.name == b.name && a.attr("Name") == b.attr("Name");
        },
        result.warnings, "dependency");
  }

  if (const auto* exts = overlay_section(*src, "Extensions")) {
    auto* dest = ensure_child(pkg, "Extensions", std::string(kNsFoundation));
    merge_children_unique(*dest, exts->children, same_extension, result.warnings,
                          "package extension");
  }

  if (const auto* app_ov = overlay_section(*src, "Application")) {
    for (const auto& a : app_ov->attributes) {
      if (application_attr_reserved(a.name)) {
        return Expected<OverlayResult>::fail(
            ExitCode::Conflict,
            "overlay Application may not set reserved attribute '" + a.name + "'");
      }
    }
    auto* apps = pkg.find_child("Applications");
    if (!apps || apps->children.empty()) {
      return Expected<OverlayResult>::fail(ExitCode::Validation,
                                           "base manifest has no Application to overlay");
    }
    XmlNode* app = &apps->children.front();
    if (const auto* want_id = app_ov->find_attr("SelectId")) {
      bool found = false;
      for (auto& c : apps->children) {
        if (c.attr("Id") == want_id->value) {
          app = &c;
          found = true;
          break;
        }
      }
      if (!found) {
        return Expected<OverlayResult>::fail(
            ExitCode::NotFound, "overlay SelectId did not match an Application");
      }
    }
    if (const auto* app_exts = app_ov->find_child("Extensions")) {
      auto* dest = ensure_child(*app, "Extensions");
      merge_children_unique(*dest, app_exts->children, same_extension, result.warnings,
                            "application extension");
    }
    if (const auto* visuals = app_ov->find_child("VisualElements")) {
      // VisualElements attributes like DisplayName are allowed; Executable/Id are not.
      for (const auto& a : visuals->attributes) {
        if (application_attr_reserved(a.name)) {
          return Expected<OverlayResult>::fail(
              ExitCode::Conflict, "overlay VisualElements reserved attribute '" + a.name + "'");
        }
      }
      if (auto* dest = app->find_child("VisualElements")) {
        for (const auto& a : visuals->attributes) {
          dest->set_attr(a.name, a.value, a.ns);
        }
        for (const auto& c : visuals->children) dest->children.push_back(c);
      } else {
        app->children.insert(app->children.begin(), *visuals);
      }
    }
  }

  // Applications section in a Package-shaped overlay: only extensions/visuals.
  if (const auto* apps_ov = overlay_section(*src, "Applications")) {
    for (const auto& app_ov : apps_ov->children) {
      if (app_ov.name != "Application") continue;
      for (const auto& a : app_ov.attributes) {
        if (application_attr_reserved(a.name) && a.name != "Id") {
          return Expected<OverlayResult>::fail(
              ExitCode::Conflict,
              "overlay Applications may not set reserved attribute '" + a.name + "'");
        }
      }
      // Selecting by Id is allowed (to target which app gets extensions).
      auto* apps = pkg.find_child("Applications");
      if (!apps) {
        return Expected<OverlayResult>::fail(ExitCode::Validation,
                                             "base manifest has no Applications");
      }
      XmlNode* app = &apps->children.front();
      const auto id = app_ov.attr("Id");
      if (!id.empty()) {
        bool found = false;
        for (auto& c : apps->children) {
          if (c.attr("Id") == id) {
            app = &c;
            found = true;
            break;
          }
        }
        if (!found) {
          return Expected<OverlayResult>::fail(
              ExitCode::NotFound, "overlay Application Id did not match");
        }
      }
      if (const auto* app_exts = app_ov.find_child("Extensions")) {
        auto* dest = ensure_child(*app, "Extensions");
        merge_children_unique(*dest, app_exts->children, same_extension, result.warnings,
                              "application extension");
      }
    }
  }

  return Expected<OverlayResult>::ok(std::move(result));
}

Expected<OverlayResult> apply_manifest_overlay_text(std::string_view base_xml,
                                                    std::string_view overlay_xml) {
  auto base = parse_xml(base_xml);
  if (!base) return Expected<OverlayResult>::fail(base.error());
  auto ov = parse_xml(overlay_xml);
  if (!ov) return Expected<OverlayResult>::fail(ov.error());
  return apply_manifest_overlay(base.value(), ov.value());
}

}  // namespace repackager
