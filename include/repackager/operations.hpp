#pragma once

#include "repackager/cli.hpp"
#include "repackager/error.hpp"
#include "repackager/report.hpp"

namespace repackager {

int dispatch_command(const ParsedCommand& cmd);

int op_list_win32(const ParsedCommand& cmd, Report& report);
int op_list_msix(const ParsedCommand& cmd, Report& report);
int op_inspect_msix(const ParsedCommand& cmd, Report& report);
int op_extract_msix(const ParsedCommand& cmd, Report& report);
int op_stage_files(const ParsedCommand& cmd, Report& report);
int op_inspect_exe(const ParsedCommand& cmd, Report& report);
int op_patch_exe_identity(const ParsedCommand& cmd, Report& report);
int op_make_manifest(const ParsedCommand& cmd, Report& report);
int op_transform_msix_manifest(const ParsedCommand& cmd, Report& report);
int op_apply_manifest_overlay(const ParsedCommand& cmd, Report& report);
int op_register_sparse(const ParsedCommand& cmd, Report& report);
int op_register_loose(const ParsedCommand& cmd, Report& report);
int op_activate(const ParsedCommand& cmd, Report& report);
int op_status(const ParsedCommand& cmd, Report& report);
int op_unregister(const ParsedCommand& cmd, Report& report);
int op_remove_retrofit(const ParsedCommand& cmd, Report& report);

}  // namespace repackager
