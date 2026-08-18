#pragma once

#include "repackager/error.hpp"
#include "repackager/json.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace repackager {

struct ElevationRequest {
  std::string operation_id;
  std::string command;
  std::vector<std::string> args;
  std::string directory;
  std::string expected_exe_sha256;
  std::string expected_exe_path;
};

bool needs_elevation_for_write(const std::filesystem::path& directory);
bool process_is_elevated();

std::filesystem::path write_elevation_request(const ElevationRequest& request);
Expected<ElevationRequest> read_elevation_request(const std::filesystem::path& path);
Status remove_elevation_request(const std::filesystem::path& path);

// Parent: write immutable request, ShellExecuteExW runas, wait, remove request.
Expected<int> elevate_self_and_wait(const ElevationRequest& request);

// Child: revalidate paths and hashes, run the recorded command.
int run_elevated_worker(const std::filesystem::path& request_path);

}  // namespace repackager
