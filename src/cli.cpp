#include "repackager/cli.hpp"

#include "repackager/operations.hpp"
#include "repackager/report.hpp"
#include "repackager/workflows.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace repackager {
namespace {

struct CommandInfo {
  Command command;
  const char* name;
  const char* usage;
};

const CommandInfo kCommands[] = {
    {Command::ListWin32, "list-win32",
     "list-win32 [--directory DIR] [--report FILE]"},
    {Command::ListMsix, "list-msix", "list-msix [--report FILE]"},
    {Command::InspectMsix, "inspect-msix",
     "inspect-msix --input FILE [--backend inbox|msix_sdk] [--report FILE]"},
    {Command::ExtractMsix, "extract-msix",
     "extract-msix --input FILE --output DIR [--backend inbox|msix_sdk] [--report FILE]"},
    {Command::StageFiles, "stage-files",
     "stage-files --source DIR --output DIR [--report FILE]"},
    {Command::InspectExe, "inspect-exe", "inspect-exe --input FILE [--report FILE]"},
    {Command::PatchExeIdentity, "patch-exe-identity",
     "patch-exe-identity --input FILE --name NAME --publisher PUB --application-id ID "
     "[--accept-signature-loss] [--report FILE]"},
    {Command::MakeManifest, "make-manifest",
     "make-manifest --layout sparse_external|loose_full --name NAME --executable REL "
     "[--version V] [--display-name T] [--application-id ID] [--architecture A] "
     "[--appcontainer] --output FILE [--report FILE]"},
    {Command::TransformMsixManifest, "transform-msix-manifest",
     "transform-msix-manifest --source FILE --name NEW --executable REL "
     "[--source-application-id ID] [--display-name T] [--application-id ID] "
     "--output FILE [--report FILE]"},
    {Command::ApplyManifestOverlay, "apply-manifest-overlay",
     "apply-manifest-overlay --manifest FILE --overlay FILE --output FILE [--report FILE]"},
    {Command::RegisterSparse, "register-sparse",
     "register-sparse --manifest FILE --external DIR [--report FILE]"},
    {Command::RegisterLoose, "register-loose", "register-loose --manifest FILE [--report FILE]"},
    {Command::Activate, "activate", "activate --aumid AUMID [--arguments TEXT] [--report FILE]"},
    {Command::Status, "status", "status --name NAME [--report FILE]"},
    {Command::Unregister, "unregister", "unregister --package-full-name NAME [--report FILE]"},
    {Command::RemoveRetrofit, "remove-retrofit",
     "remove-retrofit --name NAME [--receipt FILE] [--report FILE]"},
    {Command::RetrofitWin32Sparse, "retrofit-win32-sparse",
     "retrofit-win32-sparse --source DIR --executable REL --output DIR --name NAME "
     "[--display-name T] [--application-id ID] [--overlay-manifest FILE] "
     "[--overlay-files DIR] [--accept-signature-loss] [--prepare-only] [--launch]"},
    {Command::RetrofitWin32Inplace, "retrofit-win32-inplace",
     "retrofit-win32-inplace --directory DIR --executable REL --name NAME "
     "[--display-name T] [--application-id ID] [--appcontainer] "
     "[--overlay-manifest FILE] [--overlay-files DIR] [--prepare-only] [--launch]"},
    {Command::RetrofitMsixSparse, "retrofit-msix-sparse",
     "retrofit-msix-sparse --package-full-name FULL --output DIR --name NEW "
     "[--source-application-id ID] [--display-name T] [--application-id ID] "
     "[--overlay-manifest FILE] [--overlay-files DIR] [--accept-signature-loss] "
     "[--prepare-only] [--launch]"},
    {Command::ElevatedWorker, "elevated-worker", "elevated-worker --request FILE"},
    {Command::Help, "help", "help [COMMAND]"},
    {Command::Version, "version", "version"},
};

bool is_flag_name(std::string_view n) {
  static constexpr const char* kFlags[] = {
      "help", "prepare-only", "launch", "accept-signature-loss", "appcontainer",
      "elevated-worker"};
  return std::any_of(std::begin(kFlags), std::end(kFlags),
                     [&](const char* f) { return n == f; });
}

}  // namespace

bool ParsedCommand::has_flag(std::string_view name) const {
  return std::find(flags.begin(), flags.end(), std::string(name)) != flags.end();
}

std::optional<std::string> ParsedCommand::get(std::string_view name) const {
  auto it = options.find(std::string(name));
  if (it == options.end()) return std::nullopt;
  return it->second;
}

std::string ParsedCommand::require(std::string_view name) const {
  auto v = get(name);
  return v ? *v : std::string{};
}

std::string_view command_name(Command command) {
  for (const auto& c : kCommands) {
    if (c.command == command) return c.name;
  }
  return "unknown";
}

std::optional<Command> command_from_name(std::string_view name) {
  for (const auto& c : kCommands) {
    if (c.name == name) return c.command;
  }
  return std::nullopt;
}

std::vector<std::string_view> all_command_names() {
  std::vector<std::string_view> out;
  for (const auto& c : kCommands) out.push_back(c.name);
  return out;
}

std::string command_usage(Command command) {
  for (const auto& c : kCommands) {
    if (c.command == command) return std::string("repackager ") + c.usage;
  }
  return "repackager <command>";
}

std::string usage_text() {
  std::ostringstream os;
  os << "repackager " << REPACKAGER_VERSION << " — per-user unsigned Developer Mode packaging\n\n";
  os << "Usage: repackager <command> [options]\n\nCommands:\n";
  for (const auto& c : kCommands) {
    if (c.command == Command::ElevatedWorker) continue;
    os << "  " << c.usage << '\n';
  }
  os << "\nExit codes: 0 success, 2 usage, 3 not-found, 4 conflict, 5 validation,\n"
        "            6 signature-consent, 7 elevation, 8 rolled-back, 9 environment, 1 internal\n";
  return os.str();
}

Expected<ParsedCommand> parse_command(const std::vector<std::string>& args) {
  ParsedCommand out;
  if (args.empty()) {
    return Expected<ParsedCommand>::fail(ExitCode::Usage, "missing command");
  }
  std::size_t i = 0;
  if (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
    out.command = Command::Help;
    out.command_name = "help";
    if (args.size() > 1) out.positionals.push_back(args[1]);
    return Expected<ParsedCommand>::ok(std::move(out));
  }
  if (args[0] == "--version" || args[0] == "-V" || args[0] == "version") {
    out.command = Command::Version;
    out.command_name = "version";
    return Expected<ParsedCommand>::ok(std::move(out));
  }
  if (args[0] == "--elevated-worker") {
    out.command = Command::ElevatedWorker;
    out.command_name = "elevated-worker";
    i = 1;
  } else {
    auto cmd = command_from_name(args[0]);
    if (!cmd) {
      return Expected<ParsedCommand>::fail(ExitCode::Usage,
                                           "unknown command: " + args[0]);
    }
    out.command = *cmd;
    out.command_name = args[0];
    i = 1;
  }
  for (; i < args.size(); ++i) {
    const auto& a = args[i];
    if (a == "--help" || a == "-h") {
      out.help = true;
      continue;
    }
    if (a.rfind("--", 0) == 0) {
      std::string key = a.substr(2);
      std::string value;
      const auto eq = key.find('=');
      if (eq != std::string::npos) {
        value = key.substr(eq + 1);
        key = key.substr(0, eq);
      } else if (is_flag_name(key)) {
        out.flags.push_back(key);
        continue;
      } else if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
        value = args[++i];
      } else {
        return Expected<ParsedCommand>::fail(ExitCode::Usage, "option --" + key + " requires a value");
      }
      out.options.emplace(std::move(key), std::move(value));
      continue;
    }
    out.positionals.push_back(a);
  }
  return Expected<ParsedCommand>::ok(std::move(out));
}

Expected<ParsedCommand> parse_command(int argc, char** argv) {
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
  return parse_command(args);
}

int run_cli(const std::vector<std::string>& args) {
  auto parsed = parse_command(args);
  if (!parsed) {
    std::cerr << "ERR  usage  " << parsed.message() << '\n';
    std::cerr << "     try: repackager help\n";
    return static_cast<int>(parsed.code());
  }
  const ParsedCommand& cmd = parsed.value();
  if (cmd.command == Command::Help || cmd.help) {
    if (!cmd.positionals.empty()) {
      if (auto c = command_from_name(cmd.positionals[0])) {
        std::cout << command_usage(*c) << '\n';
        return 0;
      }
    }
    if (cmd.command != Command::Help && cmd.help) {
      std::cout << command_usage(cmd.command) << '\n';
      return 0;
    }
    std::cout << usage_text();
    return 0;
  }
  if (cmd.command == Command::Version) {
    std::cout << "repackager " << REPACKAGER_VERSION << '\n';
    return 0;
  }
  return dispatch_command(cmd);
}

int run_cli(int argc, char** argv) {
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
  return run_cli(args);
}

}  // namespace repackager
