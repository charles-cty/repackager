#pragma once

#include "repackager/cli.hpp"
#include "repackager/error.hpp"
#include "repackager/report.hpp"

namespace repackager {

int workflow_retrofit_win32_sparse(const ParsedCommand& cmd, Report& report);
int workflow_retrofit_win32_inplace(const ParsedCommand& cmd, Report& report);
int workflow_retrofit_msix_sparse(const ParsedCommand& cmd, Report& report);

}  // namespace repackager
