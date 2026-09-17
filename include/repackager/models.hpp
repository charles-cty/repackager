#pragma once

#include "repackager/error.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

inline constexpr std::string_view kUnsignedPublisher = "CN=Repackager";

inline constexpr int kReceiptSchemaVersion = 1;

enum class LayoutKind { SparseExternal, LooseFull };
enum class TrustLevel { MediumIL, AppContainer };
enum class RuntimeBehavior { Win32App, PackagedClassicApp };
enum class Architecture { Neutral, X86, X64, Arm, Arm64 };

struct PackageIdentity {
  std::string name;
  std::string publisher{kUnsignedPublisher};
  std::string version{"1.0.0.0"};
  Architecture architecture = Architecture::Neutral;
  std::string resource_id{};
};

struct ApplicationDeclaration {
  std::string id;
  std::string executable;
  RuntimeBehavior runtime = RuntimeBehavior::Win32App;
  TrustLevel trust = TrustLevel::MediumIL;
  std::string display_name{};
  std::string description{};
};

struct SourceMetadata {
  std::string kind;
  std::string path;
  std::string package_full_name;
  std::string source_application_id;
  std::vector<std::string> reported_dependencies;
};

struct Diagnostic {
  enum class Severity { Info, Warning, Error };
  Severity severity = Severity::Warning;
  std::string code{};
  std::string message{};
};

struct CreatedPath {
  std::string path;
  std::string sha256;
};

struct OperationJournal {
  std::string operation_id;
  std::string command;
  std::vector<std::string> created_paths;
  bool registered = false;
  std::string package_full_name{};
  std::string rollback_status{"none"};
  std::string journal_path{};
};

struct Receipt {
  int schema_version = kReceiptSchemaVersion;
  std::string operation_id;
  std::string command;
  PackageIdentity identity;
  LayoutKind layout = LayoutKind::SparseExternal;
  TrustLevel trust = TrustLevel::MediumIL;
  std::string package_full_name;
  std::string package_family_name;
  std::string application_id;
  std::string aumid;
  std::vector<CreatedPath> created_paths;
  std::vector<Diagnostic> warnings;
  bool elevated = false;
  std::string rollback_status{"none"};
  SourceMetadata source{};
  std::string launch_result{};
  std::string output_root{};
  std::string external_location{};
};

std::string_view to_string(LayoutKind kind);
std::string_view to_string(TrustLevel level);
std::string_view to_string(RuntimeBehavior behavior);
std::string_view to_string(Architecture arch);

Expected<LayoutKind> parse_layout_kind(std::string_view text);
Expected<TrustLevel> parse_trust_level(std::string_view text);
Expected<RuntimeBehavior> parse_runtime_behavior(std::string_view text);
Expected<Architecture> parse_architecture(std::string_view text);

}  // namespace repackager
