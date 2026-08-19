#include "repackager/manifest.hpp"

#include "repackager/identity.hpp"

#include <algorithm>

namespace repackager {
namespace {

void add_xmlns(XmlNode& n, std::string prefix, std::string uri) {
  n.xmlns.emplace_back(std::move(prefix), std::move(uri));
}

XmlNode elem(std::string name, std::string ns = std::string(kNsFoundation),
             std::string prefix = {}, std::string text = {}) {
  XmlNode n;
  n.name = std::move(name);
  n.ns = std::move(ns);
  n.prefix = std::move(prefix);
  n.text = std::move(text);
  return n;
}

XmlNode make_package_root() {
  XmlNode pkg = elem("Package");
  add_xmlns(pkg, "", std::string(kNsFoundation));
  add_xmlns(pkg, "uap", std::string(kNsUap));
  add_xmlns(pkg, "uap10", std::string(kNsUap10));
  add_xmlns(pkg, "rescap", std::string(kNsRescap));
  pkg.set_attr("IgnorableNamespaces", "uap uap10 rescap");
  return pkg;
}

XmlNode make_identity(const PackageIdentity& id) {
  auto n = elem("Identity");
  n.set_attr("Name", id.name);
  n.set_attr("Publisher", id.publisher);
  n.set_attr("Version", id.version);
  n.set_attr("ProcessorArchitecture", std::string(to_string(id.architecture)));
  if (!id.resource_id.empty()) n.set_attr("ResourceId", id.resource_id);
  return n;
}

XmlNode make_properties(const ManifestRequest& req) {
  auto props = elem("Properties");
  auto dn = elem("DisplayName");
  dn.text = req.application.display_name.empty() ? req.identity.name
                                                 : req.application.display_name;
  props.children.push_back(std::move(dn));
  auto pdn = elem("PublisherDisplayName");
  pdn.text = req.publisher_display_name;
  props.children.push_back(std::move(pdn));
  auto logo = elem("Logo");
  logo.text = req.logo;
  props.children.push_back(std::move(logo));
  if (req.allow_external_content) {
    auto aec = elem("AllowExternalContent", std::string(kNsUap10), "uap10", "true");
    props.children.push_back(std::move(aec));
  }
  return props;
}

XmlNode make_resources() {
  auto r = elem("Resources");
  auto lang = elem("Resource");
  lang.set_attr("Language", "en-us");
  r.children.push_back(std::move(lang));
  return r;
}

XmlNode make_dependencies() {
  auto d = elem("Dependencies");
  auto tdf = elem("TargetDeviceFamily");
  tdf.set_attr("Name", "Windows.Desktop");
  tdf.set_attr("MinVersion", "10.0.19041.0");
  tdf.set_attr("MaxVersionTested", "10.0.26100.0");
  d.children.push_back(std::move(tdf));
  return d;
}

XmlNode make_capabilities(const ManifestRequest& req) {
  auto c = elem("Capabilities");
  if (req.run_full_trust) {
    auto cap = elem("Capability", std::string(kNsRescap), "rescap");
    cap.set_attr("Name", "runFullTrust");
    c.children.push_back(std::move(cap));
  }
  if (req.unvirtualized_resources) {
    auto cap = elem("Capability", std::string(kNsRescap), "rescap");
    cap.set_attr("Name", "unvirtualizedResources");
    c.children.push_back(std::move(cap));
  }
  return c;
}

XmlNode make_application(const ManifestRequest& req) {
  auto app = elem("Application");
  app.set_attr("Id", req.application.id);
  app.set_attr("Executable", req.application.executable);
  // packagedClassicApp activation (IApplicationActivationManager / Start) needs
  // a real EntryPoint. Sparse win32App omits it. Overlay treats this as reserved.
  if (req.application.runtime == RuntimeBehavior::PackagedClassicApp) {
    app.set_attr("EntryPoint", req.application.trust == TrustLevel::AppContainer
                                   ? "Windows.PartialTrustApplication"
                                   : "Windows.FullTrustApplication");
  }
  app.set_attr("TrustLevel", std::string(to_string(req.application.trust)),
               std::string(kNsUap10));
  app.set_attr("RuntimeBehavior", std::string(to_string(req.application.runtime)),
               std::string(kNsUap10));
  auto vis = elem("VisualElements", std::string(kNsUap), "uap");
  vis.set_attr("DisplayName", req.application.display_name.empty()
                                  ? req.identity.name
                                  : req.application.display_name);
  vis.set_attr("Description", req.application.description.empty()
                                  ? (req.application.display_name.empty()
                                         ? req.identity.name
                                         : req.application.display_name)
                                  : req.application.description);
  vis.set_attr("BackgroundColor", "transparent");
  vis.set_attr("Square150x150Logo", req.square150);
  vis.set_attr("Square44x44Logo", req.square44);
  vis.set_attr("AppListEntry", "none");
  app.children.push_back(std::move(vis));
  return app;
}

GeneratedManifest finish(XmlNode pkg) {
  GeneratedManifest out;
  out.document.root = std::move(pkg);
  out.xml = serialize_xml(out.document, true);
  return out;
}

}  // namespace

GeneratedManifest generate_sparse_manifest(const ManifestRequest& request) {
  auto req = request;
  req.layout = LayoutKind::SparseExternal;
  req.allow_external_content = true;
  req.identity.architecture = Architecture::Neutral;
  req.application.runtime = RuntimeBehavior::Win32App;
  req.application.trust = TrustLevel::MediumIL;
  req.run_full_trust = true;
  req.unvirtualized_resources = true;

  auto pkg = make_package_root();
  pkg.children.push_back(make_identity(req.identity));
  pkg.children.push_back(make_properties(req));
  pkg.children.push_back(make_resources());
  pkg.children.push_back(make_dependencies());
  pkg.children.push_back(make_capabilities(req));
  auto apps = elem("Applications");
  apps.children.push_back(make_application(req));
  pkg.children.push_back(std::move(apps));
  return finish(std::move(pkg));
}

GeneratedManifest generate_loose_manifest(const ManifestRequest& request) {
  auto req = request;
  req.layout = LayoutKind::LooseFull;
  req.allow_external_content = false;
  req.application.runtime = RuntimeBehavior::PackagedClassicApp;
  if (req.application.trust == TrustLevel::AppContainer) {
    req.run_full_trust = false;
  } else {
    req.application.trust = TrustLevel::MediumIL;
    req.run_full_trust = true;
  }

  auto pkg = make_package_root();
  pkg.children.push_back(make_identity(req.identity));
  pkg.children.push_back(make_properties(req));
  pkg.children.push_back(make_resources());
  pkg.children.push_back(make_dependencies());
  pkg.children.push_back(make_capabilities(req));
  auto apps = elem("Applications");
  apps.children.push_back(make_application(req));
  pkg.children.push_back(std::move(apps));
  return finish(std::move(pkg));
}

GeneratedManifest generate_manifest(const ManifestRequest& request) {
  if (request.layout == LayoutKind::LooseFull) return generate_loose_manifest(request);
  return generate_sparse_manifest(request);
}

std::string create_base_exe_manifest(const MsixIdentityTuple& tuple,
                                     std::string_view assembly_name) {
  XmlDocument doc;
  doc.root = elem("assembly", std::string(kNsAsmV1));
  doc.root.xmlns.emplace_back("", std::string(kNsAsmV1));
  doc.root.set_attr("manifestVersion", "1.0");
  auto ident = elem("assemblyIdentity", std::string(kNsAsmV1));
  ident.set_attr("version", "0.0.0.0");
  ident.set_attr("name", std::string(assembly_name));
  doc.root.children.push_back(std::move(ident));
  auto msix = elem("msix", std::string(kNsMsixAsm));
  msix.xmlns.emplace_back("", std::string(kNsMsixAsm));
  msix.set_attr("publisher", tuple.publisher);
  msix.set_attr("packageName", tuple.package_name);
  msix.set_attr("applicationId", tuple.application_id);
  doc.root.children.push_back(std::move(msix));
  return serialize_xml(doc, true);
}

Expected<std::string> merge_msix_element(std::string_view existing_manifest_xml,
                                         const MsixIdentityTuple& tuple) {
  if (existing_manifest_xml.empty()) {
    return Expected<std::string>::ok(create_base_exe_manifest(tuple));
  }
  auto parsed = parse_xml(existing_manifest_xml);
  if (!parsed) return Expected<std::string>::fail(parsed.error());
  XmlDocument doc = parsed.take();
  if (doc.root.name != "assembly") {
    return Expected<std::string>::fail(ExitCode::Validation,
                                       "embedded manifest root must be assembly");
  }

  XmlNode* existing = nullptr;
  for (auto& c : doc.root.children) {
    if (c.name == "msix") {
      existing = &c;
      break;
    }
  }
  if (existing) {
    existing->set_attr("publisher", tuple.publisher);
    existing->set_attr("packageName", tuple.package_name);
    existing->set_attr("applicationId", tuple.application_id);
    if (existing->ns.empty()) existing->ns = std::string(kNsMsixAsm);
    bool has_ns = false;
    for (const auto& [p, u] : existing->xmlns) {
      if (u == kNsMsixAsm) has_ns = true;
    }
    if (!has_ns) existing->xmlns.emplace_back("", std::string(kNsMsixAsm));
  } else {
    auto msix = elem("msix", std::string(kNsMsixAsm));
    msix.xmlns.emplace_back("", std::string(kNsMsixAsm));
    msix.set_attr("publisher", tuple.publisher);
    msix.set_attr("packageName", tuple.package_name);
    msix.set_attr("applicationId", tuple.application_id);
    doc.root.children.push_back(std::move(msix));
  }
  return Expected<std::string>::ok(serialize_xml(doc, true));
}

Expected<MsixIdentityTuple> extract_msix_tuple(std::string_view manifest_xml) {
  auto parsed = parse_xml(manifest_xml);
  if (!parsed) return Expected<MsixIdentityTuple>::fail(parsed.error());
  for (const auto& c : parsed.value().root.children) {
    if (c.name == "msix") {
      MsixIdentityTuple t;
      t.publisher = c.attr("publisher");
      t.package_name = c.attr("packageName");
      t.application_id = c.attr("applicationId");
      if (t.publisher.empty() || t.package_name.empty() || t.application_id.empty()) {
        return Expected<MsixIdentityTuple>::fail(ExitCode::Validation,
                                                 "incomplete <msix> identity tuple");
      }
      return Expected<MsixIdentityTuple>::ok(std::move(t));
    }
  }
  return Expected<MsixIdentityTuple>::fail(ExitCode::NotFound,
                                           "no <msix> element in embedded manifest");
}

bool msix_tuple_matches(const MsixIdentityTuple& a, const MsixIdentityTuple& b) {
  return a.package_name == b.package_name && a.publisher == b.publisher &&
         a.application_id == b.application_id;
}

}  // namespace repackager
