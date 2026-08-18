#pragma once

#include "repackager/error.hpp"

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

enum class Command {
  Help,
  Version,
  ListWin32,
  ListMsix,
  InspectMsix,
  ExtractMsix,
  StageFiles,
  InspectExe,
  PatchExeIdentity,
  MakeManifest,
  TransformMsixManifest,
  ApplyManifestOverlay,
  RegisterSparse,
  RegisterLoose,
  Activate,
  Status,
  Unregister,
  RemoveRetrofit,
  RetrofitWin32Sparse,
  RetrofitWin32Inplace,
  RetrofitMsixSparse,
  ElevatedWorker,
};

struct ParsedCommand {
  Command command = Command::Help;
  std::string command_name;
  std::map<std::string, std::string> options;
  std::vector<std::string> flags;
  std::vector<std::string> positionals;
  bool help = false;

  bool has_flag(std::string_view name) const;
  std::optional<std::string> get(std::string_view name) const;
  std::string require(std::string_view name) const;
};

Expected<ParsedCommand> parse_command(int argc, char** argv);
Expected<ParsedCommand> parse_command(const std::vector<std::string>& args);

std::string_view command_name(Command command);
std::optional<Command> command_from_name(std::string_view name);
std::vector<std::string_view> all_command_names();
std::string usage_text();
std::string command_usage(Command command);

// Shipped CLI entry: main() is a thin wrapper. Tests call this directly.
int run_cli(int argc, char** argv);
int run_cli(const std::vector<std::string>& args);

}  // namespace repackager
