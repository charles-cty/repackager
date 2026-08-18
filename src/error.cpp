#include "repackager/error.hpp"

namespace repackager {

const char* exit_code_name(ExitCode code) {
  switch (code) {
    case ExitCode::Success:
      return "success";
    case ExitCode::Internal:
      return "internal";
    case ExitCode::Usage:
      return "usage";
    case ExitCode::NotFound:
      return "not-found";
    case ExitCode::Conflict:
      return "conflict";
    case ExitCode::Validation:
      return "validation";
    case ExitCode::SignatureConsent:
      return "signature-consent";
    case ExitCode::Elevation:
      return "elevation";
    case ExitCode::RolledBack:
      return "rolled-back";
    case ExitCode::Environment:
      return "environment";
  }
  return "unknown";
}

}  // namespace repackager
