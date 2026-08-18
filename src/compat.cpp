#include "repackager/compat.hpp"

#include "repackager/manifest.hpp"

namespace repackager {
namespace {

bool is_app_extension_category_sparse_ok(std::string_view cat) {
  // Drop in-process UWP servers and full-trust AppService hosts that require
  // packagedClassicApp / AppContainer. Keep file/protocol/startup-style extras
  // for MakeAppx to decide.
  if (cat.find("windows.inProcessServer") != std::string_view::npos) return false;
  if (cat.find("windows.activatableClass.inProcessServer") != std::string_view::npos) {
    return false;
  }
  if (cat == "windows.appService") return false;
  return true;
}

XmlNode* ensure(XmlNode& pkg, std::string name) {
  if (auto* s = pkg.find_child(name)) return s;
  XmlNode n;
  n.name = std::move(name);
  n.ns = std::string(kNsFoundation);
  pkg.children.push_back(std::move(n));
  return &pkg.children.back();
}

}  // namespace

bool sparse_incompatible_declaration(const XmlNode& node, std::string& reason) {
  if (node.name == "AllowExternalContent" && node.text == "false") {
    reason = "AllowExternalContent=false is reserved for the sparse generator";
    return true;
  }
  if (node.name == "Application") {
    const auto rb = node.attr("RuntimeBehavior");
    const auto tl = node.attr("TrustLevel");
    if (!rb.empty() && rb != "win32App") {
      reason = "sparse workflow requires RuntimeBehavior=win32App";
      return true;
    }
    if (!tl.empty() && tl != "mediumIL") {
      reason = "sparse workflow requires TrustLevel=mediumIL";
      return true;
    }
  }
  if (node.name == "Extension") {
    const auto cat = node.attr("Category");
    if (!is_app_extension_category_sparse_ok(cat)) {
      reason = "extension category incompatible with sparse win32App: " + cat;
      return true;
    }
  }
  if (node.name == "Identity") {
    reason = "source Identity is replaced by the new package identity";
    return true;
  }
  return false;
}

Expected<TransformResult> transform_msix_manifest_to_sparse(
    const XmlDocument& source, const ManifestRequest& request,
    const ManifestValidator& validator) {
  TransformResult result;
  auto generated = generate_sparse_manifest(request);
  result.manifest = generated.document;
  result.xml = generated.xml;

  if (source.root.name != "Package") {
    return Expected<TransformResult>::fail(ExitCode::Validation,
                                           "source manifest root must be Package");
  }

  auto try_add = [&](XmlNode& dest_parent, const XmlNode& incoming,
                     std::string label) -> bool {
    std::string reason;
    if (sparse_incompatible_declaration(incoming, reason)) {
      result.dropped.push_back(label);
      result.warnings.push_back(
          Diagnostic{Diagnostic::Severity::Warning, "compat-drop", reason});
      return false;
    }
    dest_parent.children.push_back(incoming);
    auto candidate = serialize_xml(result.manifest, true);
    if (validator) {
      auto st = validator(candidate);
      if (!st) {
        dest_parent.children.pop_back();
        result.dropped.push_back(label);
        result.warnings.push_back(Diagnostic{Diagnostic::Severity::Warning, "makeappx-drop",
                                             label + ": " + st.message});
        return false;
      }
    }
    result.kept.push_back(label);
    result.xml = std::move(candidate);
    return true;
  };

  if (const auto* props = source.root.find_child("Properties")) {
    auto* dest = ensure(result.manifest.root, "Properties");
    for (const auto& c : props->children) {
      if (c.name == "DisplayName" || c.name == "Logo" || c.name == "PublisherDisplayName" ||
          c.name == "AllowExternalContent") {
        // Base generator already set these; skip reserved / already-owned.
        continue;
      }
      try_add(*dest, c, "Properties/" + c.name);
    }
  }

  if (const auto* caps = source.root.find_child("Capabilities")) {
    auto* dest = ensure(result.manifest.root, "Capabilities");
    for (const auto& c : caps->children) {
      const auto name = c.attr("Name");
      if (name == "runFullTrust" || name == "unvirtualizedResources") continue;
      try_add(*dest, c, "Capability/" + (name.empty() ? c.name : name));
    }
  }

  if (const auto* deps = source.root.find_child("Dependencies")) {
    auto* dest = ensure(result.manifest.root, "Dependencies");
    for (const auto& c : deps->children) {
      if (c.name == "TargetDeviceFamily") continue;
      try_add(*dest, c, "Dependency/" + c.attr("Name", c.name));
    }
  }

  if (const auto* exts = source.root.find_child("Extensions")) {
    auto* dest = ensure(result.manifest.root, "Extensions");
    for (const auto& c : exts->children) {
      try_add(*dest, c, "PackageExtension/" + c.attr("Category", c.name));
    }
  }

  if (const auto* apps = source.root.find_child("Applications")) {
    auto* dest_apps = result.manifest.root.find_child("Applications");
    if (dest_apps && !dest_apps->children.empty()) {
      auto& dest_app = dest_apps->children.front();
      // Copy selected source application's non-reserved children (extensions).
      const XmlNode* src_app = nullptr;
      if (apps->children.size() == 1) {
        src_app = &apps->children.front();
      } else {
        for (const auto& a : apps->children) {
          if (a.attr("Id") == request.application.id ||
              a.attr("Id") == request.application.executable) {
            src_app = &a;
            break;
          }
        }
        if (!src_app) src_app = &apps->children.front();
      }
      if (const auto* app_exts = src_app->find_child("Extensions")) {
        XmlNode* dest_exts = dest_app.find_child("Extensions");
        if (!dest_exts) {
          XmlNode n;
          n.name = "Extensions";
          dest_app.children.push_back(std::move(n));
          dest_exts = &dest_app.children.back();
        }
        for (const auto& c : app_exts->children) {
          try_add(*dest_exts, c, "AppExtension/" + c.attr("Category", c.name));
        }
      }
    }
  }

  result.xml = serialize_xml(result.manifest, true);
  return Expected<TransformResult>::ok(std::move(result));
}

}  // namespace repackager
