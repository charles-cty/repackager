#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"

#include <filesystem>
#include <string>
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
  std::string signature_kind;
  std::vector<std::string> dependencies;
};

Expected<RegistrationResult> register_sparse(const RegistrationRequest& request);
Expected<RegistrationResult> register_loose(const RegistrationRequest& request);
Status unregister_package(std::string_view package_full_name);
Expected<PackageStatus> query_package_status(std::string_view name_or_full);
Expected<std::vector<InstalledPackage>> list_installed_msix();
Expected<InstalledPackage> find_installed_package(std::string_view full_name);

Status activate_aumid(std::string_view aumid, std::string_view arguments = {});
Status launch_exe(const std::filesystem::path& exe);

}  // namespace repackager
