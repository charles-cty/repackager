#include "repackager/register.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <unknwn.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlobj.h>

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Management.Deployment.h>
#include <winrt/Windows.ApplicationModel.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "repackager/identity.hpp"
#include "repackager/xml.hpp"

namespace repackager {
namespace {

std::wstring widen(std::string_view s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<std::size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

std::string narrow(std::wstring_view w) {
  if (w.empty()) return {};
  const int n =
      WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(static_cast<std::size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring file_uri(const std::filesystem::path& path) {
  auto abs = std::filesystem::absolute(path);
  std::wstring p = abs.wstring();
  for (auto& c : p)
    if (c == L'\\') c = L'/';
  if (p.size() >= 2 && p[1] == L':') {
    return L"file:///" + p;
  }
  return L"file://" + p;
}

InstalledPackage from_winrt(const winrt::Windows::ApplicationModel::Package& pkg) {
  InstalledPackage out;
  try {
    out.full_name = narrow(pkg.Id().FullName().c_str());
    out.family_name = narrow(pkg.Id().FamilyName().c_str());
    out.name = narrow(pkg.Id().Name().c_str());
    out.publisher = narrow(pkg.Id().Publisher().c_str());
    const auto v = pkg.Id().Version();
    out.version = std::to_string(v.Major) + "." + std::to_string(v.Minor) + "." +
                  std::to_string(v.Build) + "." + std::to_string(v.Revision);
    out.installed_location = narrow(pkg.InstalledLocation().Path().c_str());
    out.is_framework = pkg.IsFramework();
    out.is_resource = pkg.IsResourcePackage();
    out.is_optional = pkg.IsOptional();
    out.is_bundle = pkg.IsBundle();
    out.signature_kind = std::to_string(static_cast<int>(pkg.SignatureKind()));
    for (const auto& dep : pkg.Dependencies()) {
      out.dependencies.push_back(narrow(dep.Id().FullName().c_str()));
    }
  } catch (...) {
  }
  return out;
}

}  // namespace

Expected<RegistrationResult> win_register_package(const RegistrationRequest& request) {
  try {
    winrt::init_apartment();
    winrt::Windows::Management::Deployment::PackageManager pm;
    winrt::Windows::Management::Deployment::RegisterPackageOptions options;
    options.DeveloperMode(request.developer_mode);
    options.AllowUnsigned(request.allow_unsigned);
    if (request.sparse && !request.external_location.empty()) {
      const auto ext = file_uri(request.external_location);
      options.ExternalLocationUri(winrt::Windows::Foundation::Uri(ext));
    }
    const auto uri = winrt::Windows::Foundation::Uri(file_uri(request.manifest));
    auto op = pm.RegisterPackageByUriAsync(uri, options);
    auto result = op.get();
    if (result.IsRegistered() == false &&
        result.ExtendedErrorCode() != winrt::hresult{0}) {
      const auto err = result.ErrorText();
      return Expected<RegistrationResult>::fail(
          ExitCode::Environment, "RegisterPackageByUriAsync failed: " + narrow(err.c_str()));
    }
    RegistrationResult out;
    std::ifstream in(request.manifest);
    std::string xml((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (auto doc = parse_xml(xml)) {
      if (const auto* apps = doc.value().root.find_child("Applications")) {
        if (!apps->children.empty()) out.application_id = apps->children.front().attr("Id");
      }
      if (const auto* id = doc.value().root.find_child("Identity")) {
        PackageIdentity ident;
        ident.name = id->attr("Name");
        ident.publisher = id->attr("Publisher");
        ident.version = id->attr("Version");
        auto arch = parse_architecture(id->attr("ProcessorArchitecture", "neutral"));
        if (arch) ident.architecture = arch.value();
        ident.resource_id = id->attr("ResourceId");
        out.package_family_name = package_family_name(ident);
        out.package_full_name = package_full_name(ident);
      }
    }
    if (!out.package_full_name.empty()) {
      for (const auto& pkg : pm.FindPackagesForUser(L"")) {
        if (narrow(pkg.Id().FullName().c_str()) == out.package_full_name) {
          out.installed_location = narrow(pkg.InstalledLocation().Path().c_str());
          break;
        }
      }
    }
    out.aumid = make_aumid(out.package_family_name, out.application_id);
    out.external_location = request.external_location.string();
    return Expected<RegistrationResult>::ok(std::move(out));
  } catch (const winrt::hresult_error& e) {
    return Expected<RegistrationResult>::fail(
        ExitCode::Environment, "PackageManager exception: " + narrow(e.message().c_str()));
  } catch (const std::exception& e) {
    return Expected<RegistrationResult>::fail(ExitCode::Environment, e.what());
  }
}

Status win_unregister_package(std::string_view package_full_name) {
  try {
    winrt::init_apartment();
    winrt::Windows::Management::Deployment::PackageManager pm;
    auto result = pm.RemovePackageAsync(widen(package_full_name)).get();
    const auto hr = result.ExtendedErrorCode();
    if (FAILED(hr)) {
      const auto err = narrow(result.ErrorText().c_str());
      if (is_package_not_installed_status(hr.value, err)) {
        return Status::success();
      }
      return Status::fail(ExitCode::Environment, "RemovePackageAsync failed: " + err);
    }
    return Status::success();
  } catch (const winrt::hresult_error& e) {
    const auto err = narrow(e.message().c_str());
    if (is_package_not_installed_status(e.code().value, err)) {
      return Status::success();
    }
    return Status::fail(ExitCode::Environment, err);
  }
}

Expected<PackageStatus> win_query_package_status(std::string_view name_or_full) {
  try {
    winrt::init_apartment();
    winrt::Windows::Management::Deployment::PackageManager pm;
    PackageStatus st;
    for (const auto& pkg : pm.FindPackagesForUser(L"")) {
      const auto full = narrow(pkg.Id().FullName().c_str());
      const auto name = narrow(pkg.Id().Name().c_str());
      if (full == name_or_full || name == name_or_full) {
        st.registered = true;
        st.package_full_name = full;
        st.package_family_name = narrow(pkg.Id().FamilyName().c_str());
        st.installed_location = narrow(pkg.InstalledLocation().Path().c_str());
        st.publisher = narrow(pkg.Id().Publisher().c_str());
        const auto v = pkg.Id().Version();
        st.version = std::to_string(v.Major) + "." + std::to_string(v.Minor) + "." +
                     std::to_string(v.Build) + "." + std::to_string(v.Revision);
        try {
          const auto ps = pkg.Status();
          st.ok = ps.VerifyIsOK();
          st.needs_remediation = ps.NeedsRemediation();
          st.modified = ps.Modified();
        } catch (...) {
        }
        return Expected<PackageStatus>::ok(std::move(st));
      }
    }
    return Expected<PackageStatus>::ok(std::move(st));
  } catch (const winrt::hresult_error& e) {
    return Expected<PackageStatus>::fail(ExitCode::Environment, narrow(e.message().c_str()));
  }
}

Expected<std::vector<InstalledPackage>> win_list_installed_msix() {
  try {
    winrt::init_apartment();
    winrt::Windows::Management::Deployment::PackageManager pm;
    std::vector<InstalledPackage> out;
    for (const auto& pkg : pm.FindPackagesForUser(L"")) {
      out.push_back(from_winrt(pkg));
    }
    return Expected<std::vector<InstalledPackage>>::ok(std::move(out));
  } catch (const winrt::hresult_error& e) {
    return Expected<std::vector<InstalledPackage>>::fail(ExitCode::Environment,
                                                         narrow(e.message().c_str()));
  }
}

Expected<InstalledPackage> win_find_installed_package(std::string_view full_name) {
  auto all = win_list_installed_msix();
  if (!all) return Expected<InstalledPackage>::fail(all.error());
  for (const auto& p : all.value()) {
    if (p.full_name == full_name) return Expected<InstalledPackage>::ok(p);
  }
  return Expected<InstalledPackage>::fail(ExitCode::NotFound,
                                          "installed package not found: " + std::string(full_name));
}

Status win_activate_aumid(std::string_view aumid, std::string_view arguments) {
  const HRESULT com_hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool com_inited = SUCCEEDED(com_hr);
  IApplicationActivationManager* aam = nullptr;
  HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, nullptr, CLSCTX_LOCAL_SERVER,
                                IID_IApplicationActivationManager, reinterpret_cast<void**>(&aam));
  if (FAILED(hr) || !aam) {
    if (com_inited) CoUninitialize();
    return Status::fail(ExitCode::Environment, "IApplicationActivationManager unavailable");
  }
  DWORD pid = 0;
  const auto w = widen(aumid);
  const auto args = widen(arguments);
  hr = aam->ActivateApplication(w.c_str(), args.c_str(), AO_NONE, &pid);
  aam->Release();
  if (com_inited) CoUninitialize();
  if (FAILED(hr)) {
    char hex[16];
    std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(hr));
    return Status::fail(ExitCode::Environment,
                        std::string("ActivateApplication failed HRESULT=") + hex);
  }
  return Status::success();
}

Status win_launch_exe(const std::filesystem::path& exe) {
  SHELLEXECUTEINFOW sei{};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb = L"open";
  sei.lpFile = exe.c_str();
  sei.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteExW(&sei)) {
    return Status::fail(ExitCode::Environment, "ShellExecuteExW failed to launch staged EXE");
  }
  if (sei.hProcess) CloseHandle(sei.hProcess);
  return Status::success();
}

}  // namespace repackager
#endif
