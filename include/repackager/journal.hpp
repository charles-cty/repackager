#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

// Fault-injection hook used by tests. Invoked with a stage name before/after
// mutations. Throw or return a failed Status to abort.
using FaultHook = std::function<Status(std::string_view stage)>;

void set_fault_hook(FaultHook hook);
void clear_fault_hook();
Status fault_checkpoint(std::string_view stage);

std::string new_operation_id();

Status write_journal(const std::filesystem::path& path, const OperationJournal& journal);
Expected<OperationJournal> read_journal(const std::filesystem::path& path);

Status journal_record_path(OperationJournal& journal, const std::filesystem::path& path);

// Unregister (if recorded) and delete only journal-recorded files, never the
// original executable or unrelated paths.
struct RollbackHooks {
  std::function<Status(std::string_view package_full_name)> unregister;
};

Status rollback_journal(const OperationJournal& journal,
                        const RollbackHooks& hooks = {},
                        const std::filesystem::path& original_exe = {});

}  // namespace repackager
