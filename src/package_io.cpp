#include "repackager/package_io.hpp"

#include "repackager/hash.hpp"
#include "repackager/identity.hpp"
#include "repackager/manifest.hpp"
#include "repackager/xml.hpp"
#include "repackager/zip.hpp"

#include <fstream>

namespace repackager {
namespace {

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    char ca = a[i], cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
    if (ca != cb) return false;
  }
  return true;
}

Expected<MsixInspection> inspect_from_entries(const std::vector<ZipEntry>& entries,
                                              std::string backend) {
  MsixInspection info;
  info.backend = std::move(backend);
  const ZipEntry* manifest = nullptr;
  for (const auto& e : entries) {
    if (iequals(e.name, "AppxManifest.xml")) manifest = &e;
    if (is_msix_footprint_file(e.name)) {
      info.footprint_files.push_back(e.name);
    } else if (!e.is_directory) {
      info.payload_files.push_back(e.name);
    }
    if (iequals(e.name, "AppxMetadata/CodeIntegrity.cat") ||
        e.name.find("Encrypted") != std::string::npos) {
      // Encrypted Store payloads typically ship an EncryptedAppxHeader.
    }
  }
  for (const auto& e : entries) {
    if (e.name.find("AppxMetadata/Encrypted") != std::string::npos ||
        iequals(e.name, "AppxMetadata/EncryptedAppxHeader")) {
      info.encrypted = true;
    }
  }
  if (!manifest) {
    return Expected<MsixInspection>::fail(ExitCode::Validation,
                                          "package has no AppxManifest.xml");
  }
  info.manifest_xml.assign(manifest->data.begin(), manifest->data.end());
  auto doc = parse_xml(info.manifest_xml);
  if (!doc) return Expected<MsixInspection>::fail(doc.error());
  if (const auto* id = doc.value().root.find_child("Identity")) {
    info.identity.name = id->attr("Name");
    info.identity.publisher = id->attr("Publisher");
    info.identity.version = id->attr("Version");
    auto arch = parse_architecture(id->attr("ProcessorArchitecture", "neutral"));
    if (arch) info.identity.architecture = arch.value();
    info.identity.resource_id = id->attr("ResourceId");
  }
  if (const auto* apps = doc.value().root.find_child("Applications")) {
    for (const auto& a : apps->children) {
      if (a.name != "Application") continue;
      ApplicationDeclaration d;
      d.id = a.attr("Id");
      d.executable = a.attr("Executable");
      auto rb = parse_runtime_behavior(a.attr("RuntimeBehavior", "packagedClassicApp"));
      if (rb) d.runtime = rb.value();
      auto tl = parse_trust_level(a.attr("TrustLevel", "mediumIL"));
      if (tl) d.trust = tl.value();
      if (const auto* vis = a.find_child("VisualElements")) {
        d.display_name = vis->attr("DisplayName");
        d.description = vis->attr("Description");
      }
      info.applications.push_back(std::move(d));
    }
  }
  if (info.encrypted) {
    info.warnings.push_back(Diagnostic{Diagnostic::Severity::Error, "encrypted",
                                       "package payload is encrypted and cannot be copied"});
  }
  return Expected<MsixInspection>::ok(std::move(info));
}

class ZipBackend : public IPackageIo {
 public:
  explicit ZipBackend(std::string name) : name_(std::move(name)) {}
  std::string backend_name() const override { return name_; }

  Expected<MsixInspection> inspect(const std::filesystem::path& package) override {
    auto entries = zip_read(package);
    if (!entries) return Expected<MsixInspection>::fail(entries.error());
    return inspect_from_entries(entries.value(), name_);
  }

  Expected<ExtractResult> extract(const std::filesystem::path& package,
                                  const std::filesystem::path& destination) override {
    auto entries = zip_read(package);
    if (!entries) return Expected<ExtractResult>::fail(entries.error());
    ExtractResult out;
    out.destination = destination;
    std::error_code ec;
    std::filesystem::create_directories(destination, ec);
    for (const auto& e : entries.value()) {
      if (e.is_directory) continue;
      const auto dest = destination / e.name;
      std::filesystem::create_directories(dest.parent_path(), ec);
      std::ofstream f(dest, std::ios::binary | std::ios::trunc);
      if (!f) {
        return Expected<ExtractResult>::fail(ExitCode::Internal,
                                             "cannot write " + dest.string());
      }
      if (!e.data.empty()) {
        f.write(reinterpret_cast<const char*>(e.data.data()),
                static_cast<std::streamsize>(e.data.size()));
      }
      CreatedPath cp{dest.string(), sha256_file_hex(dest)};
      out.files.push_back(std::move(cp));
      if (iequals(e.name, "AppxManifest.xml")) out.manifest = dest;
    }
    return Expected<ExtractResult>::ok(std::move(out));
  }

 private:
  std::string name_;
};

}  // namespace

bool is_msix_footprint_file(std::string_view relative) {
  const auto slash = relative.find_last_of("/\\");
  const auto name = slash == std::string_view::npos ? relative : relative.substr(slash + 1);
  if (iequals(name, "AppxBlockMap.xml") || iequals(name, "AppxSignature.p7x") ||
      iequals(name, "[Content_Types].xml")) {
    return true;
  }
  if (relative.size() >= 13) {
    auto prefix = relative.substr(0, 13);
    if (iequals(prefix, "AppxMetadata/") || iequals(prefix, "AppxMetadata\\")) return true;
  }
  return iequals(relative, "AppxMetadata");
}

#ifdef _WIN32
std::unique_ptr<IPackageIo> create_inbox_appx_packaging_io();
#ifdef REPACKAGER_HAVE_MSIX_SDK
std::unique_ptr<IPackageIo> create_msix_sdk_io();
#endif
#endif

std::unique_ptr<IPackageIo> create_package_io(PackageIoBackend backend) {
#ifdef _WIN32
  if (backend == PackageIoBackend::Inbox) {
    if (auto p = create_inbox_appx_packaging_io()) return p;
  }
#ifdef REPACKAGER_HAVE_MSIX_SDK
  if (backend == PackageIoBackend::MsixSdk) {
    if (auto p = create_msix_sdk_io()) return p;
  }
#endif
#endif
  if (backend == PackageIoBackend::MsixSdk) {
    return std::make_unique<ZipBackend>("msix_sdk");
  }
  return std::make_unique<ZipBackend>("inbox");
}

std::vector<PackageIoBackend> available_package_io_backends() {
  return {PackageIoBackend::Inbox, PackageIoBackend::MsixSdk};
}

}  // namespace repackager
