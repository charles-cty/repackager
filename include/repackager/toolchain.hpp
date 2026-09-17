#pragma once

#include "repackager/error.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace repackager {

struct ProcessResult {
  int exit_code = 0;
  std::string stdout_text;
  std::string stderr_text;
};

struct SdkTools {
  std::filesystem::path mt_exe;
  std::filesystem::path makeappx_exe;
  std::string sdk_version;
};

Expected<SdkTools> locate_windows_sdk_tools();
Expected<std::filesystem::path> locate_mt_exe();
Expected<std::filesystem::path> locate_makeappx_exe();
Expected<std::filesystem::path> locate_signtool_exe();

Expected<std::string> normalize_sha1_thumbprint(std::string_view thumbprint);
Status sign_executable_with_thumbprint(const std::filesystem::path& executable,
                                       std::string_view thumbprint,
                                       std::string_view publisher);

// Invoke an executable directly (CreateProcess / posix_spawn). Never a shell.
Expected<ProcessResult> run_process(const std::filesystem::path& exe,
                                    const std::vector<std::string>& args,
                                    const std::filesystem::path& cwd = {});

Status validate_manifest_with_makeappx(const std::filesystem::path& layout_dir,
                                       const std::filesystem::path& makeappx = {},
                                       bool skip_semantic = true);

}  // namespace repackager
