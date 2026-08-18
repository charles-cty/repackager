#include "repackager/toolchain.hpp"

#include <algorithm>
#include <cstdlib>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace repackager {
namespace {

#ifdef _WIN32
std::wstring widen(const std::string& s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<std::size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

std::string quote_arg(const std::string& a) {
  if (a.find_first_of(" \t\"") == std::string::npos) return a;
  std::string o = "\"";
  for (char c : a) {
    if (c == '"') o += "\\\"";
    else o.push_back(c);
  }
  o += '"';
  return o;
}
#endif

std::filesystem::path first_existing(const std::vector<std::filesystem::path>& cands) {
  std::error_code ec;
  for (const auto& c : cands) {
    if (std::filesystem::exists(c, ec)) return c;
  }
  return {};
}

std::vector<std::filesystem::path> sdk_bin_roots() {
  std::vector<std::filesystem::path> roots;
  if (const char* kit = std::getenv("WindowsSdkVerBinPath")) {
    if (*kit) roots.emplace_back(kit);
  }
  const std::filesystem::path kits = "C:/Program Files (x86)/Windows Kits/10/bin";
  std::error_code ec;
  if (std::filesystem::exists(kits, ec)) {
    std::vector<std::filesystem::path> vers;
    for (auto& e : std::filesystem::directory_iterator(kits, ec)) {
      if (e.is_directory()) vers.push_back(e.path());
    }
    std::sort(vers.begin(), vers.end());
    std::reverse(vers.begin(), vers.end());
    roots.insert(roots.end(), vers.begin(), vers.end());
  }
  roots.emplace_back("C:/Program Files (x86)/Windows Kits/10/App Certification Kit");
  return roots;
}

}  // namespace

Expected<std::filesystem::path> locate_mt_exe() {
  std::vector<std::filesystem::path> cands;
  for (const auto& root : sdk_bin_roots()) {
    cands.push_back(root / "x64" / "mt.exe");
    cands.push_back(root / "x86" / "mt.exe");
    cands.push_back(root / "mt.exe");
  }
  auto p = first_existing(cands);
  if (p.empty()) {
    return Expected<std::filesystem::path>::fail(ExitCode::Environment, "mt.exe not found");
  }
  return Expected<std::filesystem::path>::ok(std::move(p));
}

Expected<std::filesystem::path> locate_makeappx_exe() {
  std::vector<std::filesystem::path> cands;
  for (const auto& root : sdk_bin_roots()) {
    cands.push_back(root / "x64" / "makeappx.exe");
    cands.push_back(root / "x64" / "MakeAppx.exe");
    cands.push_back(root / "x86" / "makeappx.exe");
    cands.push_back(root / "MakeAppx.exe");
  }
  auto p = first_existing(cands);
  if (p.empty()) {
    return Expected<std::filesystem::path>::fail(ExitCode::Environment, "MakeAppx.exe not found");
  }
  return Expected<std::filesystem::path>::ok(std::move(p));
}

Expected<SdkTools> locate_windows_sdk_tools() {
  SdkTools t;
  auto mt = locate_mt_exe();
  auto mx = locate_makeappx_exe();
  if (mt) t.mt_exe = mt.value();
  if (mx) t.makeappx_exe = mx.value();
  if (t.mt_exe.empty() && t.makeappx_exe.empty()) {
    return Expected<SdkTools>::fail(ExitCode::Environment, "Windows SDK packaging tools not found");
  }
  if (!t.mt_exe.empty()) t.sdk_version = t.mt_exe.parent_path().parent_path().filename().string();
  return Expected<SdkTools>::ok(std::move(t));
}

Expected<ProcessResult> run_process(const std::filesystem::path& exe,
                                    const std::vector<std::string>& args,
                                    const std::filesystem::path& cwd) {
  ProcessResult result;
#ifdef _WIN32
  std::string cmd = quote_arg(exe.string());
  for (const auto& a : args) {
    cmd.push_back(' ');
    cmd += quote_arg(a);
  }
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE out_r = nullptr, out_w = nullptr, err_r = nullptr, err_w = nullptr;
  if (!CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&err_r, &err_w, &sa, 0)) {
    return Expected<ProcessResult>::fail(ExitCode::Internal, "CreatePipe failed");
  }
  SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = out_w;
  si.hStdError = err_w;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION pi{};
  std::wstring wcmd = widen(cmd);
  std::wstring wdir = cwd.empty() ? std::wstring() : cwd.wstring();
  const BOOL ok = CreateProcessW(exe.wstring().c_str(), wcmd.data(), nullptr, nullptr, TRUE,
                                 CREATE_NO_WINDOW, nullptr, wdir.empty() ? nullptr : wdir.c_str(),
                                 &si, &pi);
  CloseHandle(out_w);
  CloseHandle(err_w);
  if (!ok) {
    CloseHandle(out_r);
    CloseHandle(err_r);
    return Expected<ProcessResult>::fail(ExitCode::Environment,
                                         "CreateProcessW failed for " + exe.string());
  }
  auto read_all = [](HANDLE h, std::string& dst) {
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n) dst.append(buf, buf + n);
  };
  read_all(out_r, result.stdout_text);
  read_all(err_r, result.stderr_text);
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  result.exit_code = static_cast<int>(code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(out_r);
  CloseHandle(err_r);
  return Expected<ProcessResult>::ok(std::move(result));
#else
  // Direct exec (no shell): fork + execv.
  int out_pipe[2];
  int err_pipe[2];
  if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
    return Expected<ProcessResult>::fail(ExitCode::Internal, "pipe() failed");
  }
  const pid_t pid = fork();
  if (pid < 0) {
    return Expected<ProcessResult>::fail(ExitCode::Internal, "fork() failed");
  }
  if (pid == 0) {
    if (!cwd.empty()) {
      if (chdir(cwd.string().c_str()) != 0) _exit(127);
    }
    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(err_pipe[1], STDERR_FILENO);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    std::vector<std::string> storage;
    storage.push_back(exe.string());
    storage.insert(storage.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (auto& s : storage) argv.push_back(s.data());
    argv.push_back(nullptr);
    execv(exe.c_str(), argv.data());
    _exit(127);
  }
  close(out_pipe[1]);
  close(err_pipe[1]);
  char buf[4096];
  ssize_t n = 0;
  while ((n = read(out_pipe[0], buf, sizeof(buf))) > 0) {
    result.stdout_text.append(buf, buf + n);
  }
  while ((n = read(err_pipe[0], buf, sizeof(buf))) > 0) {
    result.stderr_text.append(buf, buf + n);
  }
  close(out_pipe[0]);
  close(err_pipe[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
  return Expected<ProcessResult>::ok(std::move(result));
#endif
}

Status validate_manifest_with_makeappx(const std::filesystem::path& layout_dir,
                                       const std::filesystem::path& makeappx, bool skip_semantic) {
  std::filesystem::path tool = makeappx;
  if (tool.empty()) {
    auto found = locate_makeappx_exe();
    if (!found) return Status::fail(found.code(), found.message());
    tool = found.value();
  }
  const auto packed = layout_dir / ".repackager-validate.msix";
  std::vector<std::string> args = {"pack", "/o", "/d", layout_dir.string(), "/p", packed.string()};
  if (skip_semantic) args.insert(args.begin() + 1, "/nv");
  auto r = run_process(tool, args, layout_dir);
  std::error_code ec;
  std::filesystem::remove(packed, ec);
  if (!r) return Status::fail(r.code(), r.message());
  if (r.value().exit_code != 0) {
    return Status::fail(ExitCode::Validation,
                        "MakeAppx rejected layout: " + r.value().stderr_text +
                            r.value().stdout_text);
  }
  return Status::success();
}

}  // namespace repackager
