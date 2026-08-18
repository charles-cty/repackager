#include "repackager/register.hpp"

#include "repackager/identity.hpp"
#include "repackager/xml.hpp"

#include <fstream>

#ifdef _WIN32
// Real implementations live in src/win/package_manager.cpp
namespace repackager {
Expected<RegistrationResult> win_register_package(const RegistrationRequest& request);
Status win_unregister_package(std::string_view package_full_name);
Expected<PackageStatus> win_query_package_status(std::string_view name_or_full);
Expected<std::vector<InstalledPackage>> win_list_installed_msix();
Expected<InstalledPackage> win_find_installed_package(std::string_view full_name);
Status win_activate_aumid(std::string_view aumid, std::string_view arguments);
Status win_launch_exe(const std::filesystem::path& exe);
}  // namespace repackager
#endif

namespace repackager {
namespace {

Expected<RegistrationResult> result_from_manifest(const RegistrationRequest& request) {
  std::ifstream in(request.manifest);
  if (!in) {
    return Expected<RegistrationResult>::fail(ExitCode::NotFound,
                                              "manifest not found: " + request.manifest.string());
  }
  std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto doc = parse_xml(xml);
  if (!doc) return Expected<RegistrationResult>::fail(doc.error());
  RegistrationResult r;
  if (const auto* id = doc.value().root.find_child("Identity")) {
    PackageIdentity ident;
    ident.name = id->attr("Name");
    ident.publisher = id->attr("Publisher");
    ident.version = id->attr("Version");
    auto arch = parse_architecture(id->attr("ProcessorArchitecture", "neutral"));
    if (arch) ident.architecture = arch.value();
    ident.resource_id = id->attr("ResourceId");
    r.package_full_name = package_full_name(ident);
    r.package_family_name = package_family_name(ident);
  }
  if (const auto* apps = doc.value().root.find_child("Applications")) {
    if (!apps->children.empty()) {
      r.application_id = apps->children.front().attr("Id");
    }
  }
  r.aumid = make_aumid(r.package_family_name, r.application_id);
  r.installed_location = request.manifest.parent_path().string();
  r.external_location = request.external_location.string();
  return Expected<RegistrationResult>::ok(std::move(r));
}

}  // namespace

Expected<RegistrationResult> register_sparse(const RegistrationRequest& request) {
  auto req = request;
  req.sparse = true;
  req.developer_mode = true;
  req.allow_unsigned = true;
#ifdef _WIN32
  return win_register_package(req);
#else
  return result_from_manifest(req);
#endif
}

Expected<RegistrationResult> register_loose(const RegistrationRequest& request) {
  auto req = request;
  req.sparse = false;
  req.external_location.clear();
  req.developer_mode = true;
  req.allow_unsigned = true;
#ifdef _WIN32
  return win_register_package(req);
#else
  return result_from_manifest(req);
#endif
}

Status unregister_package(std::string_view package_full_name) {
#ifdef _WIN32
  return win_unregister_package(package_full_name);
#else
  (void)package_full_name;
  return Status::success();
#endif
}

Expected<PackageStatus> query_package_status(std::string_view name_or_full) {
#ifdef _WIN32
  return win_query_package_status(name_or_full);
#else
  PackageStatus s;
  s.registered = false;
  s.package_full_name = std::string(name_or_full);
  return Expected<PackageStatus>::ok(std::move(s));
#endif
}

Expected<std::vector<InstalledPackage>> list_installed_msix() {
#ifdef _WIN32
  return win_list_installed_msix();
#else
  return Expected<std::vector<InstalledPackage>>::ok({});
#endif
}

Expected<InstalledPackage> find_installed_package(std::string_view full_name) {
#ifdef _WIN32
  return win_find_installed_package(full_name);
#else
  return Expected<InstalledPackage>::fail(
      ExitCode::Environment, "PackageManager is only available on Windows; cannot resolve " +
                                 std::string(full_name));
#endif
}

Status activate_aumid(std::string_view aumid, std::string_view arguments) {
#ifdef _WIN32
  return win_activate_aumid(aumid, arguments);
#else
  (void)arguments;
  return Status::fail(ExitCode::Environment,
                      "IApplicationActivationManager is only available on Windows (" +
                          std::string(aumid) + ")");
#endif
}

Status launch_exe(const std::filesystem::path& exe) {
#ifdef _WIN32
  return win_launch_exe(exe);
#else
  return Status::fail(ExitCode::Environment,
                      "direct EXE launch is only available on Windows: " + exe.string());
#endif
}

}  // namespace repackager
