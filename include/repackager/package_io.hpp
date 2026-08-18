#pragma once

#include "repackager/error.hpp"
#include "repackager/models.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace repackager {

enum class PackageIoBackend { Inbox, MsixSdk };

struct MsixInspection {
  std::string backend;
  PackageIdentity identity;
  std::vector<ApplicationDeclaration> applications;
  std::string manifest_xml;
  std::vector<std::string> payload_files;
  bool encrypted = false;
  std::vector<std::string> footprint_files;
  std::vector<Diagnostic> warnings;
};

struct ExtractResult {
  std::filesystem::path destination;
  std::filesystem::path manifest;
  std::vector<CreatedPath> files;
};

class IPackageIo {
 public:
  virtual ~IPackageIo() = default;
  virtual std::string backend_name() const = 0;
  virtual Expected<MsixInspection> inspect(const std::filesystem::path& package) = 0;
  virtual Expected<ExtractResult> extract(const std::filesystem::path& package,
                                          const std::filesystem::path& destination) = 0;
};

std::unique_ptr<IPackageIo> create_package_io(PackageIoBackend backend);
std::vector<PackageIoBackend> available_package_io_backends();

bool is_msix_footprint_file(std::string_view relative);

}  // namespace repackager
