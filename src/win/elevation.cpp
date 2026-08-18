#include "repackager/elevate.hpp"
#include "repackager/cli.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

#include <fstream>

namespace repackager {

bool win_process_is_elevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elev{};
  DWORD len = 0;
  const BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &len);
  CloseHandle(token);
  return ok && elev.TokenIsElevated;
}

bool win_needs_elevation_for_write(const std::filesystem::path& directory) {
  std::error_code ec;
  std::filesystem::create_directories(directory, ec);
  const auto probe = directory / ".repackager-write-probe";
  HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
  if (h == INVALID_HANDLE_VALUE) return true;
  CloseHandle(h);
  return false;
}

Expected<int> win_elevate_self_and_wait(const ElevationRequest& request) {
  const auto req_path = write_elevation_request(request);
  wchar_t module[MAX_PATH]{};
  GetModuleFileNameW(nullptr, module, MAX_PATH);
  std::wstring params = L"--elevated-worker --request \"" + req_path.wstring() + L"\"";
  SHELLEXECUTEINFOW sei{};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb = L"runas";
  sei.lpFile = module;
  sei.lpParameters = params.c_str();
  sei.nShow = SW_HIDE;
  if (!ShellExecuteExW(&sei)) {
    remove_elevation_request(req_path);
    return Expected<int>::fail(ExitCode::Elevation, "ShellExecuteExW runas failed");
  }
  DWORD code = static_cast<DWORD>(ExitCode::Elevation);
  if (sei.hProcess) {
    WaitForSingleObject(sei.hProcess, INFINITE);
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
  }
  remove_elevation_request(req_path);
  return Expected<int>::ok(static_cast<int>(code));
}

int win_run_elevated_worker(const std::filesystem::path& request_path) {
  auto req = read_elevation_request(request_path);
  if (!req) return static_cast<int>(req.code());
  std::vector<std::string> args;
  args.push_back(req.value().command);
  args.insert(args.end(), req.value().args.begin(), req.value().args.end());
  return run_cli(args);
}

}  // namespace repackager
#endif
