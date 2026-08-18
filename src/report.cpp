#include "repackager/report.hpp"

#include <fstream>
#include <sstream>

namespace repackager {

void report_line(Report& report, std::string line) { report.lines.push_back(std::move(line)); }

void report_kv(Report& report, std::string_view key, std::string_view value) {
  std::string line;
  line.reserve(4 + key.size() + 2 + value.size());
  line.append("    ");
  line.append(key);
  if (key.size() < 16) line.append(16 - key.size(), ' ');
  else line.push_back(' ');
  line.append(value);
  report.lines.push_back(std::move(line));
}

std::string format_human(const Report& report) {
  std::ostringstream os;
  const char* tag = report.exit_code == ExitCode::Success ? "OK" : "ERR";
  os << tag << "  " << report.command;
  if (!report.summary.empty()) os << "  " << report.summary;
  os << '\n';
  for (const auto& line : report.lines) os << line << '\n';
  for (const auto& d : report.diagnostics) {
    os << "    " << (d.severity == Diagnostic::Severity::Error ? "error" : "warning");
    if (!d.code.empty()) os << '[' << d.code << ']';
    os << "  " << d.message << '\n';
  }
  if (!report.path.empty()) os << "    report          " << report.path.string() << '\n';
  return os.str();
}

Status write_report_file(const Report& report) {
  if (report.path.empty()) return Status::success();
  std::error_code ec;
  std::filesystem::create_directories(report.path.parent_path(), ec);
  std::ofstream out(report.path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return Status::fail(ExitCode::Internal, "cannot write report: " + report.path.string());
  }
  out << format_human(report);
  return Status::success();
}

}  // namespace repackager
