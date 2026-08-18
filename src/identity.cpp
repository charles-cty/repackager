#include "repackager/identity.hpp"

#include "repackager/hash.hpp"
#include "repackager/models.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace repackager {
namespace {

bool is_alnum(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

std::string to_lower_copy(std::string_view s) {
  std::string o(s);
  std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return o;
}

}  // namespace

std::string_view to_string(LayoutKind kind) {
  switch (kind) {
    case LayoutKind::SparseExternal:
      return "sparse_external";
    case LayoutKind::LooseFull:
      return "loose_full";
  }
  return "unknown";
}

std::string_view to_string(TrustLevel level) {
  switch (level) {
    case TrustLevel::MediumIL:
      return "mediumIL";
    case TrustLevel::AppContainer:
      return "appContainer";
  }
  return "unknown";
}

std::string_view to_string(RuntimeBehavior behavior) {
  switch (behavior) {
    case RuntimeBehavior::Win32App:
      return "win32App";
    case RuntimeBehavior::PackagedClassicApp:
      return "packagedClassicApp";
  }
  return "unknown";
}

std::string_view to_string(Architecture arch) {
  switch (arch) {
    case Architecture::Neutral:
      return "neutral";
    case Architecture::X86:
      return "x86";
    case Architecture::X64:
      return "x64";
    case Architecture::Arm:
      return "arm";
    case Architecture::Arm64:
      return "arm64";
  }
  return "unknown";
}

Expected<LayoutKind> parse_layout_kind(std::string_view text) {
  const auto t = to_lower_copy(text);
  if (t == "sparse_external" || t == "sparse" || t == "sparse-external") {
    return Expected<LayoutKind>::ok(LayoutKind::SparseExternal);
  }
  if (t == "loose_full" || t == "loose" || t == "loose-full" || t == "ordinary-loose") {
    return Expected<LayoutKind>::ok(LayoutKind::LooseFull);
  }
  return Expected<LayoutKind>::fail(ExitCode::Usage,
                                    "unknown layout kind: " + std::string(text));
}

Expected<TrustLevel> parse_trust_level(std::string_view text) {
  const auto t = to_lower_copy(text);
  if (t == "mediumil" || t == "medium") {
    return Expected<TrustLevel>::ok(TrustLevel::MediumIL);
  }
  if (t == "appcontainer" || t == "app-container") {
    return Expected<TrustLevel>::ok(TrustLevel::AppContainer);
  }
  return Expected<TrustLevel>::fail(ExitCode::Usage,
                                    "unknown trust level: " + std::string(text));
}

Expected<RuntimeBehavior> parse_runtime_behavior(std::string_view text) {
  const auto t = to_lower_copy(text);
  if (t == "win32app" || t == "win32") {
    return Expected<RuntimeBehavior>::ok(RuntimeBehavior::Win32App);
  }
  if (t == "packagedclassicapp" || t == "packaged-classic" || t == "classic") {
    return Expected<RuntimeBehavior>::ok(RuntimeBehavior::PackagedClassicApp);
  }
  return Expected<RuntimeBehavior>::fail(
      ExitCode::Usage, "unknown runtime behavior: " + std::string(text));
}

Expected<Architecture> parse_architecture(std::string_view text) {
  const auto t = to_lower_copy(text);
  if (t == "neutral") return Expected<Architecture>::ok(Architecture::Neutral);
  if (t == "x86" || t == "win32") return Expected<Architecture>::ok(Architecture::X86);
  if (t == "x64" || t == "amd64" || t == "x86_64") {
    return Expected<Architecture>::ok(Architecture::X64);
  }
  if (t == "arm") return Expected<Architecture>::ok(Architecture::Arm);
  if (t == "arm64" || t == "aarch64") return Expected<Architecture>::ok(Architecture::Arm64);
  return Expected<Architecture>::fail(ExitCode::Usage,
                                      "unknown architecture: " + std::string(text));
}

Status validate_package_name(std::string_view name) {
  if (name.size() < 3 || name.size() > 50) {
    return Status::fail(ExitCode::Validation,
                        "package name must be 3-50 characters");
  }
  if (name.front() == '.' || name.back() == '.') {
    return Status::fail(ExitCode::Validation,
                        "package name cannot start or end with '.'");
  }
  for (char c : name) {
    if (!(is_alnum(c) || c == '.' || c == '-')) {
      return Status::fail(ExitCode::Validation,
                          "package name may contain only A-Z, a-z, 0-9, '.' and '-'");
    }
  }
  return Status::success();
}

Status validate_publisher(std::string_view publisher) {
  if (publisher.size() < 4 || publisher.substr(0, 3) != "CN=") {
    return Status::fail(ExitCode::Validation, "publisher must start with CN=");
  }
  if (publisher.size() > 8192) {
    return Status::fail(ExitCode::Validation, "publisher is too long");
  }
  return Status::success();
}

Status validate_version(std::string_view version) {
  int parts = 0;
  std::size_t i = 0;
  while (i < version.size()) {
    if (parts > 0) {
      if (version[i] != '.') {
        return Status::fail(ExitCode::Validation,
                            "version must be four dot-separated integers");
      }
      ++i;
    }
    if (i >= version.size() || version[i] < '0' || version[i] > '9') {
      return Status::fail(ExitCode::Validation,
                          "version must be four dot-separated integers 0-65535");
    }
    unsigned value = 0;
    while (i < version.size() && version[i] >= '0' && version[i] <= '9') {
      value = value * 10 + static_cast<unsigned>(version[i] - '0');
      if (value > 65535) {
        return Status::fail(ExitCode::Validation, "version component exceeds 65535");
      }
      ++i;
    }
    ++parts;
  }
  if (parts != 4) {
    return Status::fail(ExitCode::Validation, "version must have exactly four components");
  }
  return Status::success();
}

Status validate_application_id(std::string_view id) {
  if (id.empty() || id.size() > 64) {
    return Status::fail(ExitCode::Validation, "application id must be 1-64 characters");
  }
  if (!((id[0] >= 'A' && id[0] <= 'Z') || (id[0] >= 'a' && id[0] <= 'z'))) {
    return Status::fail(ExitCode::Validation, "application id must start with a letter");
  }
  for (char c : id) {
    if (!(is_alnum(c) || c == '.' || c == '-')) {
      return Status::fail(ExitCode::Validation,
                          "application id may contain only A-Z, a-z, 0-9, '.' and '-'");
    }
  }
  return Status::success();
}

Status validate_identity(const PackageIdentity& identity) {
  if (auto s = validate_package_name(identity.name); !s) return s;
  if (auto s = validate_publisher(identity.publisher); !s) return s;
  if (auto s = validate_version(identity.version); !s) return s;
  return Status::success();
}

std::string publisher_id(std::string_view publisher) {
  const auto utf = utf16le(publisher);
  const auto digest = sha256_bytes(utf.data(), utf.size());
  static constexpr char kAlphabet[] = "0123456789abcdefghjkmnpqrstvwxyz";
  std::string bits;
  bits.reserve(65);
  for (int i = 0; i < 8; ++i) {
    for (int b = 7; b >= 0; --b) {
      bits.push_back(((digest[i] >> b) & 1) ? '1' : '0');
    }
  }
  bits.push_back('0');
  std::string out;
  out.reserve(13);
  for (int i = 0; i < 13; ++i) {
    int v = 0;
    for (int b = 0; b < 5; ++b) {
      v = (v << 1) | (bits[static_cast<std::size_t>(i * 5 + b)] == '1' ? 1 : 0);
    }
    out.push_back(kAlphabet[v]);
  }
  return out;
}

std::string package_family_name(const PackageIdentity& identity) {
  return identity.name + "_" + publisher_id(identity.publisher);
}

std::string package_full_name(const PackageIdentity& identity) {
  return identity.name + "_" + identity.version + "_" +
         std::string(to_string(identity.architecture)) + "_" + identity.resource_id +
         "_" + publisher_id(identity.publisher);
}

std::string make_aumid(std::string_view family_name, std::string_view application_id) {
  std::string out;
  out.reserve(family_name.size() + 1 + application_id.size());
  out.append(family_name);
  out.push_back('!');
  out.append(application_id);
  return out;
}

std::string sanitize_application_id(std::string_view exe_stem) {
  std::string out;
  out.reserve(exe_stem.size());
  for (char c : exe_stem) {
    if (is_alnum(c) || c == '.' || c == '-') {
      out.push_back(c);
    } else if (c == '_' || c == ' ') {
      if (!out.empty() && out.back() != '-') out.push_back('-');
    }
  }
  while (!out.empty() && (out.front() == '.' || out.front() == '-')) out.erase(out.begin());
  while (!out.empty() && (out.back() == '.' || out.back() == '-')) out.pop_back();
  if (out.empty() || !((out[0] >= 'A' && out[0] <= 'Z') || (out[0] >= 'a' && out[0] <= 'z'))) {
    out = "App" + out;
  }
  if (out.size() > 64) out.resize(64);
  return out;
}

std::string default_unsigned_publisher() {
  return std::string(kUnsignedPublisher);
}

}  // namespace repackager
