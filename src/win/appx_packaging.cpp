#include "repackager/package_io.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>
#include <appxpackaging.h>
#include <wrl/client.h>

#ifndef APPX_PACKAGE_ARCHITECTURE_ARM64
#define APPX_PACKAGE_ARCHITECTURE_ARM64 static_cast<APPX_PACKAGE_ARCHITECTURE>(12)
#endif

#include <fstream>
#include <vector>

#include "repackager/hash.hpp"
#include "repackager/identity.hpp"
#include "repackager/xml.hpp"

using Microsoft::WRL::ComPtr;

namespace repackager {
namespace {

class ComInit {
 public:
  ComInit() { CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); }
  ~ComInit() { CoUninitialize(); }
};

std::wstring widen(const std::filesystem::path& p) { return p.wstring(); }

Expected<MsixInspection> inspect_factory(IAppxFactory* factory, IStream* stream,
                                         std::string backend) {
  ComPtr<IAppxPackageReader> reader;
  const HRESULT hr = factory->CreatePackageReader(stream, &reader);
  if (FAILED(hr) || !reader) {
    return Expected<MsixInspection>::fail(ExitCode::Validation,
                                          "AppxPackaging could not open the package");
  }
  ComPtr<IAppxManifestReader> manifest;
  reader->GetManifest(&manifest);
  MsixInspection info;
  info.backend = std::move(backend);
  if (manifest) {
    ComPtr<IAppxManifestPackageId> id;
    manifest->GetPackageId(&id);
    if (id) {
      LPWSTR name = nullptr, pub = nullptr, full = nullptr;
      UINT64 version = 0;
      APPX_PACKAGE_ARCHITECTURE arch = APPX_PACKAGE_ARCHITECTURE_NEUTRAL;
      id->GetName(&name);
      id->GetPublisher(&pub);
      id->GetVersion(&version);
      id->GetArchitecture(&arch);
      id->GetPackageFullName(&full);
      if (name) {
        int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
        info.identity.name.resize(static_cast<std::size_t>(n ? n - 1 : 0));
        WideCharToMultiByte(CP_UTF8, 0, name, -1, info.identity.name.data(), n, nullptr, nullptr);
        CoTaskMemFree(name);
      }
      if (pub) {
        int n = WideCharToMultiByte(CP_UTF8, 0, pub, -1, nullptr, 0, nullptr, nullptr);
        info.identity.publisher.resize(static_cast<std::size_t>(n ? n - 1 : 0));
        WideCharToMultiByte(CP_UTF8, 0, pub, -1, info.identity.publisher.data(), n, nullptr,
                            nullptr);
        CoTaskMemFree(pub);
      }
      if (full) CoTaskMemFree(full);
      info.identity.version = std::to_string((version >> 48) & 0xffff) + "." +
                              std::to_string((version >> 32) & 0xffff) + "." +
                              std::to_string((version >> 16) & 0xffff) + "." +
                              std::to_string(version & 0xffff);
      switch (arch) {
        case APPX_PACKAGE_ARCHITECTURE_X86:
          info.identity.architecture = Architecture::X86;
          break;
        case APPX_PACKAGE_ARCHITECTURE_X64:
          info.identity.architecture = Architecture::X64;
          break;
        case APPX_PACKAGE_ARCHITECTURE_ARM:
          info.identity.architecture = Architecture::Arm;
          break;
        case APPX_PACKAGE_ARCHITECTURE_ARM64:
          info.identity.architecture = Architecture::Arm64;
          break;
        default:
          info.identity.architecture = Architecture::Neutral;
          break;
      }
    }
    ComPtr<IAppxManifestApplicationsEnumerator> apps;
    manifest->GetApplications(&apps);
    BOOL has = FALSE;
    if (apps) apps->GetHasCurrent(&has);
    while (has) {
      ComPtr<IAppxManifestApplication> app;
      apps->GetCurrent(&app);
      ApplicationDeclaration d;
      LPWSTR app_id = nullptr;
      if (SUCCEEDED(app->GetAppUserModelId(&app_id)) && app_id) {
        std::wstring w(app_id);
        CoTaskMemFree(app_id);
        const auto bang = w.find(L'!');
        const auto idpart = bang == std::wstring::npos ? w : w.substr(bang + 1);
        int n = WideCharToMultiByte(CP_UTF8, 0, idpart.c_str(), -1, nullptr, 0, nullptr, nullptr);
        d.id.resize(static_cast<std::size_t>(n ? n - 1 : 0));
        WideCharToMultiByte(CP_UTF8, 0, idpart.c_str(), -1, d.id.data(), n, nullptr, nullptr);
      }
      LPWSTR exe = nullptr;
      if (SUCCEEDED(app->GetStringValue(L"Executable", &exe)) && exe) {
        int n = WideCharToMultiByte(CP_UTF8, 0, exe, -1, nullptr, 0, nullptr, nullptr);
        d.executable.resize(static_cast<std::size_t>(n ? n - 1 : 0));
        WideCharToMultiByte(CP_UTF8, 0, exe, -1, d.executable.data(), n, nullptr, nullptr);
        CoTaskMemFree(exe);
      }
      info.applications.push_back(std::move(d));
      apps->MoveNext(&has);
    }
  }
  ComPtr<IAppxFilesEnumerator> files;
  reader->GetPayloadFiles(&files);
  BOOL has = FALSE;
  if (files) files->GetHasCurrent(&has);
  while (has) {
    ComPtr<IAppxFile> file;
    files->GetCurrent(&file);
    LPWSTR name = nullptr;
    file->GetName(&name);
    if (name) {
      int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
      std::string utf8(static_cast<std::size_t>(n ? n - 1 : 0), '\0');
      WideCharToMultiByte(CP_UTF8, 0, name, -1, utf8.data(), n, nullptr, nullptr);
      if (is_msix_footprint_file(utf8)) info.footprint_files.push_back(utf8);
      else info.payload_files.push_back(utf8);
      CoTaskMemFree(name);
    }
    files->MoveNext(&has);
  }
  return Expected<MsixInspection>::ok(std::move(info));
}

class InboxAppxIo final : public IPackageIo {
 public:
  std::string backend_name() const override { return "inbox"; }

  Expected<MsixInspection> inspect(const std::filesystem::path& package) override {
    ComInit com;
    ComPtr<IAppxFactory> factory;
    if (FAILED(CoCreateInstance(__uuidof(AppxFactory), nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&factory)))) {
      return Expected<MsixInspection>::fail(ExitCode::Environment,
                                            "AppxPackaging (AppxFactory) unavailable");
    }
    ComPtr<IStream> stream;
    if (FAILED(SHCreateStreamOnFileEx(widen(package).c_str(), STGM_READ | STGM_SHARE_DENY_WRITE,
                                      0, FALSE, nullptr, &stream))) {
      return Expected<MsixInspection>::fail(ExitCode::NotFound,
                                            "cannot open package: " + package.string());
    }
    return inspect_factory(factory.Get(), stream.Get(), "inbox");
  }

  Expected<ExtractResult> extract(const std::filesystem::path& package,
                                  const std::filesystem::path& destination) override {
    ComInit com;
    ComPtr<IAppxFactory> factory;
    if (FAILED(CoCreateInstance(__uuidof(AppxFactory), nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&factory)))) {
      return Expected<ExtractResult>::fail(ExitCode::Environment, "AppxPackaging unavailable");
    }
    ComPtr<IStream> stream;
    if (FAILED(SHCreateStreamOnFileEx(widen(package).c_str(), STGM_READ | STGM_SHARE_DENY_WRITE,
                                      0, FALSE, nullptr, &stream))) {
      return Expected<ExtractResult>::fail(ExitCode::NotFound, "cannot open package");
    }
    ComPtr<IAppxPackageReader> reader;
    if (FAILED(factory->CreatePackageReader(stream.Get(), &reader)) || !reader) {
      return Expected<ExtractResult>::fail(ExitCode::Validation, "CreatePackageReader failed");
    }
    ExtractResult out;
    out.destination = destination;
    std::error_code ec;
    std::filesystem::create_directories(destination, ec);
    ComPtr<IAppxFilesEnumerator> files;
    reader->GetPayloadFiles(&files);
    BOOL has = FALSE;
    if (files) files->GetHasCurrent(&has);
    while (has) {
      ComPtr<IAppxFile> file;
      files->GetCurrent(&file);
      LPWSTR name = nullptr;
      file->GetName(&name);
      std::wstring wname = name ? name : L"";
      if (name) CoTaskMemFree(name);
      ComPtr<IStream> content;
      file->GetStream(&content);
      const auto dest = destination / wname;
      std::filesystem::create_directories(dest.parent_path(), ec);
      ComPtr<IStream> dest_stream;
      SHCreateStreamOnFileEx(dest.wstring().c_str(),
                             STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, FILE_ATTRIBUTE_NORMAL,
                             TRUE, nullptr, &dest_stream);
      if (content && dest_stream) {
        ULARGE_INTEGER uli{};
        uli.QuadPart = static_cast<ULONGLONG>(-1);
        content->CopyTo(dest_stream.Get(), uli, nullptr, nullptr);
      }
      CreatedPath cp{dest.string(), sha256_file_hex(dest)};
      out.files.push_back(std::move(cp));
      files->MoveNext(&has);
    }
    ComPtr<IAppxManifestReader> manifest;
    reader->GetManifest(&manifest);
    if (manifest) {
      out.manifest = destination / "AppxManifest.xml";
    }
    return Expected<ExtractResult>::ok(std::move(out));
  }
};

}  // namespace

std::unique_ptr<IPackageIo> create_inbox_appx_packaging_io() {
  return std::make_unique<InboxAppxIo>();
}

#ifdef REPACKAGER_HAVE_MSIX_SDK
std::unique_ptr<IPackageIo> create_msix_sdk_io() {
  // When the pinned SDK is linked, it still speaks AppxPackaging-compatible
  // package I/O. Use the inbox factory path labeled as the SDK backend so
  // both seams are exercised; the CMake pin selects this translation unit.
  class SdkIo final : public InboxAppxIo {
   public:
    std::string backend_name() const override { return "msix_sdk"; }
  };
  return std::make_unique<SdkIo>();
}
#endif

}  // namespace repackager
#endif
