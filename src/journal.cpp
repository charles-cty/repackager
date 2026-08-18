#include "repackager/journal.hpp"

#include "repackager/json.hpp"
#include "repackager/paths.hpp"

#include <chrono>
#include <fstream>
#include <random>
#include <sstream>

namespace repackager {
namespace {

FaultHook g_fault_hook;

Json journal_to_json(const OperationJournal& j) {
  JsonObject o;
  o["operationId"] = Json::string(j.operation_id);
  o["command"] = Json::string(j.command);
  JsonArray paths;
  for (const auto& p : j.created_paths) paths.push_back(Json::string(p));
  o["createdPaths"] = Json::array(std::move(paths));
  o["registered"] = Json::boolean(j.registered);
  o["packageFullName"] = Json::string(j.package_full_name);
  o["rollbackStatus"] = Json::string(j.rollback_status);
  o["journalPath"] = Json::string(j.journal_path);
  return Json::object(std::move(o));
}

}  // namespace

void set_fault_hook(FaultHook hook) { g_fault_hook = std::move(hook); }
void clear_fault_hook() { g_fault_hook = {}; }

Status fault_checkpoint(std::string_view stage) {
  if (g_fault_hook) return g_fault_hook(stage);
  return Status::success();
}

std::string new_operation_id() {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;
  std::ostringstream os;
  os << std::hex << ms << "-" << dist(gen);
  return os.str();
}

Status write_journal(const std::filesystem::path& path, const OperationJournal& journal) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return Status::fail(ExitCode::Internal, "cannot write journal: " + path.string());
  }
  auto copy = journal;
  copy.journal_path = path.string();
  out << serialize_json(journal_to_json(copy), true);
  return Status::success();
}

Expected<OperationJournal> read_journal(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return Expected<OperationJournal>::fail(ExitCode::NotFound,
                                            "journal not found: " + path.string());
  }
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto j = parse_json(text);
  if (!j) return Expected<OperationJournal>::fail(j.error());
  OperationJournal out;
  out.operation_id = j.value().get_string("operationId");
  out.command = j.value().get_string("command");
  if (const auto* p = j.value().get("createdPaths"); p && p->is_array()) {
    for (const auto& x : p->as_array()) out.created_paths.push_back(x.as_string());
  }
  out.registered = j.value().get_bool("registered", false);
  out.package_full_name = j.value().get_string("packageFullName");
  out.rollback_status = j.value().get_string("rollbackStatus", "none");
  out.journal_path = j.value().get_string("journalPath", path.string());
  return Expected<OperationJournal>::ok(std::move(out));
}

Status journal_record_path(OperationJournal& journal, const std::filesystem::path& path) {
  journal.created_paths.push_back(path.string());
  if (!journal.journal_path.empty()) {
    return write_journal(journal.journal_path, journal);
  }
  return Status::success();
}

Status rollback_journal(const OperationJournal& journal, const RollbackHooks& hooks,
                        const std::filesystem::path& original_exe) {
  Status last = Status::success();
  if (journal.registered && hooks.unregister && !journal.package_full_name.empty()) {
    last = hooks.unregister(journal.package_full_name);
  }
  auto paths = journal.created_paths;
  for (auto it = paths.rbegin(); it != paths.rend(); ++it) {
    const std::filesystem::path p(*it);
    if (!original_exe.empty()) {
      std::error_code ec;
      if (std::filesystem::equivalent(p, original_exe, ec)) {
        return Status::fail(ExitCode::Internal,
                            "rollback refused to delete original executable");
      }
    }
    std::error_code ec;
    if (std::filesystem::is_directory(p, ec)) {
      // Only remove if empty after children were deleted; otherwise leave.
      std::filesystem::remove(p, ec);
    } else {
      std::filesystem::remove(p, ec);
    }
  }
  if (!journal.journal_path.empty()) {
    std::error_code ec;
    std::filesystem::remove(journal.journal_path, ec);
  }
  return last;
}

}  // namespace repackager
