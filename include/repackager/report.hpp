#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

struct Report {
  std::string command;
  ExitCode exit_code = ExitCode::Success;
  std::string summary;
  std::vector<std::string> lines;
  std::vector<Diagnostic> diagnostics;
  std::filesystem::path path;
};

void report_line(Report& report, std::string line);
void report_kv(Report& report, std::string_view key, std::string_view value);
std::string format_human(const Report& report);
Status write_report_file(const Report& report);

}  // namespace repackager
