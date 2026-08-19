#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

struct RegistrationRequest {
  std::filesystem::path manifest;
  std::filesystem::path external_location;  // empty for ordinary loose
  bool developer_mode = true;
  bool allow_unsigned = true;
  bool sparse = false;
};

struct RegistrationResult {
  std::string package_full_name;
  std::string package_family_name;
  std::string aumid;
  std::string application_id;
  std::string installed_location;
  std::string external_location;
};

struct PackageStatus {
  bool registered = false;
  std::string package_full_name;
  std::string package_family_name;
  std::string installed_location;
  std::string publisher;
  std::string version;
  std::vector<std::string> aumids;
  bool signature_kind_unsigned = false;
  bool ok = true;
  bool needs_remediation{};
  bool modified{};
};

struct InstalledPackage {
  std::string full_name;
  std::string family_name;
  std::string name;
  std::string publisher;
  std::string version;
  std::string installed_location;
  bool is_framework = false;
  bool is_resource = false;
  bool is_optional = false;
  bool is_bundle = false;
  std::string signature_kind{};
  std::vector<std::string> dependencies{};
};

Expected<RegistrationResult> register_sparse(const RegistrationRequest& request);
Expected<RegistrationResult> register_loose(const RegistrationRequest& request);
Status unregister_package(std::string_view package_full_name);
Expected<PackageStatus> query_package_status(std::string_view name_or_full);

// True when `query` is the package name, family name (PFN), full name, or an AUMID
// whose family prefix matches (`FamilyName!ApplicationId`).
bool package_query_matches(std::string_view query, std::string_view name,
                           std::string_view family_name, std::string_view full_name);
Expected<std::vector<InstalledPackage>> list_installed_msix();
Expected<InstalledPackage> find_installed_package(std::string_view full_name);

Status activate_aumid(std::string_view aumid, std::string_view arguments = {});
Status launch_exe(const std::filesystem::path& exe);

// True when RemovePackageAsync failed because the package is already gone.
// HRESULTs include ERROR_INSTALL_PACKAGE_NOT_FOUND (0x80073CF1).
bool is_package_not_installed_status(std::int32_t hresult, std::string_view message);

}  // namespace repackager
