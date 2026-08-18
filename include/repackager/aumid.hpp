#pragma once

#include "repackager/identity.hpp"

namespace repackager {

// AUMID is PackageFamilyName!ApplicationId. This header exists so tests can
// include the construction helper independently of the rest of identity.
inline std::string construct_aumid(std::string_view family_name,
                                   std::string_view application_id) {
  return make_aumid(family_name, application_id);
}

}  // namespace repackager
