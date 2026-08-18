#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"

#include <string>
#include <string_view>

namespace repackager {

Status validate_package_name(std::string_view name);
Status validate_publisher(std::string_view publisher);
Status validate_version(std::string_view version);
Status validate_application_id(std::string_view id);
Status validate_identity(const PackageIdentity& identity);

std::string publisher_id(std::string_view publisher);
std::string package_family_name(const PackageIdentity& identity);
std::string package_full_name(const PackageIdentity& identity);
std::string make_aumid(std::string_view family_name, std::string_view application_id);

std::string sanitize_application_id(std::string_view exe_stem);
std::string default_unsigned_publisher();

}  // namespace repackager
