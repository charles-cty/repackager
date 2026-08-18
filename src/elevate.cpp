#include "repackager/elevate.hpp"

#include "repackager/hash.hpp"
#include "repackager/paths.hpp"

#include <fstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace repackager {

#ifdef _WIN32
int win_run_elevated_worker(const std::filesystem::path& request_path);
Expected<int> win_elevate_self_and_wait(const ElevationRequest& request);
bool win_process_is_elevated();
bool win_needs_elevation_for_write(const std::filesystem::path& directory);
#endif

bool needs_elevation_for_write(const std::filesystem::path& directory) {
#ifdef _WIN32
  return win_needs_elevation_for_write(directory);
#else
  std::error_code ec;
  auto probe = directory / ".repackager-write-probe";
  std::filesystem::create_directories(directory, ec);
  std::ofstream out(probe);
  if (!out) return true;
  out.close();
  std::filesystem::remove(probe, ec);
  return false;
#endif
}

bool process_is_elevated() {
#ifdef _WIN32
  return win_process_is_elevated();
#else
  return false;
#endif
}

std::filesystem::path write_elevation_request(const ElevationRequest& request) {
  const auto dir = elevate_request_dir();
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  const auto path = dir / (request.operation_id + ".json");
  JsonObject o;
  o["operationId"] = Json::string(request.operation_id);
  o["command"] = Json::string(request.command);
  JsonArray args;
  for (const auto& a : request.args) args.push_back(Json::string(a));
  o["args"] = Json::array(std::move(args));
  o["directory"] = Json::string(request.directory);
  o["expectedExeSha256"] = Json::string(request.expected_exe_sha256);
  o["expectedExePath"] = Json::string(request.expected_exe_path);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << serialize_json(Json::object(std::move(o)), true);
  std::filesystem::permissions(path, std::filesystem::perms::owner_read,
                               std::filesystem::perm_options::replace, ec);
  return path;
}

Expected<ElevationRequest> read_elevation_request(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return Expected<ElevationRequest>::fail(ExitCode::NotFound,
                                            "elevation request missing: " + path.string());
  }
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto j = parse_json(text);
  if (!j) return Expected<ElevationRequest>::fail(j.error());
  ElevationRequest r;
  r.operation_id = j.value().get_string("operationId");
  r.command = j.value().get_string("command");
  r.directory = j.value().get_string("directory");
  r.expected_exe_sha256 = j.value().get_string("expectedExeSha256");
  r.expected_exe_path = j.value().get_string("expectedExePath");
  if (const auto* a = j.value().get("args"); a && a->is_array()) {
    for (const auto& x : a->as_array()) r.args.push_back(x.as_string());
  }
  return Expected<ElevationRequest>::ok(std::move(r));
}

Status remove_elevation_request(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
  return Status::success();
}

Expected<int> elevate_self_and_wait(const ElevationRequest& request) {
#ifdef _WIN32
  return win_elevate_self_and_wait(request);
#else
  (void)request;
  return Expected<int>::fail(ExitCode::Environment,
                             "UAC elevation (ShellExecuteExW runas) is only available on Windows");
#endif
}

int run_elevated_worker(const std::filesystem::path& request_path) {
  auto req = read_elevation_request(request_path);
  if (!req) return static_cast<int>(req.code());
  if (!req.value().expected_exe_path.empty()) {
    std::error_code ec;
    if (!std::filesystem::exists(req.value().expected_exe_path, ec)) {
      remove_elevation_request(request_path);
      return static_cast<int>(ExitCode::NotFound);
    }
    if (!req.value().expected_exe_sha256.empty()) {
      const auto actual = sha256_file_hex(req.value().expected_exe_path);
      if (actual != req.value().expected_exe_sha256) {
        remove_elevation_request(request_path);
        return static_cast<int>(ExitCode::Validation);
      }
    }
  }
#ifdef _WIN32
  const int code = win_run_elevated_worker(request_path);
#else
  const int code = static_cast<int>(ExitCode::Environment);
#endif
  remove_elevation_request(request_path);
  return code;
}

}  // namespace repackager
