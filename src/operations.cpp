#include "repackager/operations.hpp"

#include "repackager/assets.hpp"
#include "repackager/cli.hpp"
#include "repackager/compat.hpp"
#include "repackager/elevate.hpp"
#include "repackager/hash.hpp"
#include "repackager/identity.hpp"
#include "repackager/journal.hpp"
#include "repackager/manifest.hpp"
#include "repackager/overlay.hpp"
#include "repackager/package_io.hpp"
#include "repackager/paths.hpp"
#include "repackager/pe.hpp"
#include "repackager/receipt.hpp"
#include "repackager/register.hpp"
#include "repackager/stage.hpp"
#include "repackager/toolchain.hpp"
#include "repackager/workflows.hpp"
#include "repackager/xml.hpp"

#include <fstream>
#include <iostream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace repackager {
namespace {

int finish(Report& report, int code) {
  report.exit_code = static_cast<ExitCode>(code);
  const auto text = format_human(report);
  if (code == 0) std::cout << text;
  else std::cerr << text;
  if (!report.path.empty()) write_report_file(report);
  return code;
}

int fail(Report& report, ExitCode code, std::string message) {
  report.summary = std::move(message);
  return finish(report, static_cast<int>(code));
}

std::filesystem::path opt_path(const ParsedCommand& cmd, std::string_view key) {
  if (auto v = cmd.get(key)) return std::filesystem::path(*v);
  return {};
}

void attach_report_path(const ParsedCommand& cmd, Report& report) {
  if (auto v = cmd.get("report")) report.path = *v;
}

PackageIoBackend backend_from(const ParsedCommand& cmd) {
  if (auto v = cmd.get("backend")) {
    if (*v == "msix_sdk" || *v == "sdk") return PackageIoBackend::MsixSdk;
  }
  return PackageIoBackend::Inbox;
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

Status write_text(const std::filesystem::path& path, std::string_view text) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return Status::fail(ExitCode::Internal, "cannot write " + path.string());
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
  return Status::success();
}

}  // namespace

int dispatch_command(const ParsedCommand& cmd) {
  Report report;
  report.command = cmd.command_name;
  attach_report_path(cmd, report);
  switch (cmd.command) {
    case Command::ListWin32:
      return op_list_win32(cmd, report);
    case Command::ListMsix:
      return op_list_msix(cmd, report);
    case Command::InspectMsix:
      return op_inspect_msix(cmd, report);
    case Command::ExtractMsix:
      return op_extract_msix(cmd, report);
    case Command::StageFiles:
      return op_stage_files(cmd, report);
    case Command::InspectExe:
      return op_inspect_exe(cmd, report);
    case Command::PatchExeIdentity:
      return op_patch_exe_identity(cmd, report);
    case Command::MakeManifest:
      return op_make_manifest(cmd, report);
    case Command::TransformMsixManifest:
      return op_transform_msix_manifest(cmd, report);
    case Command::ApplyManifestOverlay:
      return op_apply_manifest_overlay(cmd, report);
    case Command::RegisterSparse:
      return op_register_sparse(cmd, report);
    case Command::RegisterLoose:
      return op_register_loose(cmd, report);
    case Command::Activate:
      return op_activate(cmd, report);
    case Command::Status:
      return op_status(cmd, report);
    case Command::Unregister:
      return op_unregister(cmd, report);
    case Command::RemoveRetrofit:
      return op_remove_retrofit(cmd, report);
    case Command::RetrofitWin32Sparse:
      return workflow_retrofit_win32_sparse(cmd, report);
    case Command::RetrofitWin32Inplace:
      return workflow_retrofit_win32_inplace(cmd, report);
    case Command::RetrofitMsixSparse:
      return workflow_retrofit_msix_sparse(cmd, report);
    case Command::ElevatedWorker: {
      auto req = opt_path(cmd, "request");
      if (req.empty()) return fail(report, ExitCode::Usage, "missing --request");
      return run_elevated_worker(req);
    }
    default:
      return fail(report, ExitCode::Usage, "unsupported command");
  }
}

int op_list_win32(const ParsedCommand& cmd, Report& report) {
  const auto dir = opt_path(cmd, "directory");
  if (dir.empty()) {
#ifdef _WIN32
    report.summary = "scan --directory to list EXEs (registry enumeration not required)";
    return fail(report, ExitCode::Usage, "missing --directory");
#else
    return fail(report, ExitCode::Usage, "missing --directory");
#endif
  }
  std::error_code ec;
  if (!std::filesystem::exists(dir, ec)) {
    return fail(report, ExitCode::NotFound, "directory not found");
  }
  int n = 0;
  for (auto it = std::filesystem::recursive_directory_iterator(
           dir, std::filesystem::directory_options::skip_permission_denied, ec);
       it != std::filesystem::recursive_directory_iterator(); ++it) {
    if (!it->is_regular_file()) continue;
    if (it->path().extension() == ".exe" || it->path().extension() == ".EXE") {
      report_kv(report, "exe", it->path().string());
      ++n;
    }
  }
  report.summary = std::to_string(n) + " executable(s)";
  return finish(report, 0);
}

int op_list_msix(const ParsedCommand&, Report& report) {
  auto pkgs = list_installed_msix();
  if (!pkgs) return fail(report, pkgs.code(), pkgs.message());
  for (const auto& p : pkgs.value()) {
    report_line(report, std::string("    ") + p.full_name);
    report_kv(report, "location", p.installed_location);
  }
  report.summary = std::to_string(pkgs.value().size()) + " package(s)";
  return finish(report, 0);
}

int op_inspect_msix(const ParsedCommand& cmd, Report& report) {
  const auto input = opt_path(cmd, "input");
  if (input.empty()) return fail(report, ExitCode::Usage, "missing --input");
  auto io = create_package_io(backend_from(cmd));
  auto info = io->inspect(input);
  if (!info) return fail(report, info.code(), info.message());
  report.summary = info.value().identity.name;
  report_kv(report, "backend", info.value().backend);
  report_kv(report, "name", info.value().identity.name);
  report_kv(report, "publisher", info.value().identity.publisher);
  report_kv(report, "version", info.value().identity.version);
  report_kv(report, "encrypted", info.value().encrypted ? "yes" : "no");
  for (const auto& a : info.value().applications) {
    report_kv(report, "application", a.id + " (" + a.executable + ")");
  }
  if (info.value().encrypted) {
    report.diagnostics.push_back(
        Diagnostic{Diagnostic::Severity::Error, "encrypted", "payload is encrypted"});
    return finish(report, static_cast<int>(ExitCode::Validation));
  }
  return finish(report, 0);
}

int op_extract_msix(const ParsedCommand& cmd, Report& report) {
  const auto input = opt_path(cmd, "input");
  const auto output = opt_path(cmd, "output");
  if (input.empty() || output.empty()) {
    return fail(report, ExitCode::Usage, "missing --input or --output");
  }
  if (!directory_is_absent_or_empty(output)) {
    return fail(report, ExitCode::Conflict, "output is not empty");
  }
  auto io = create_package_io(backend_from(cmd));
  auto r = io->extract(input, output);
  if (!r) return fail(report, r.code(), r.message());
  report.summary = output.string();
  report_kv(report, "files", std::to_string(r.value().files.size()));
  return finish(report, 0);
}

int op_stage_files(const ParsedCommand& cmd, Report& report) {
  StageOptions opt;
  opt.source = opt_path(cmd, "source");
  opt.destination = opt_path(cmd, "output");
  if (opt.source.empty() || opt.destination.empty()) {
    return fail(report, ExitCode::Usage, "missing --source or --output");
  }
  auto r = stage_files(opt);
  if (!r) return fail(report, r.code(), r.message());
  report.summary = std::to_string(r.value().file_count) + " file(s)";
  return finish(report, 0);
}

int op_inspect_exe(const ParsedCommand& cmd, Report& report) {
  auto input = opt_path(cmd, "input");
  if (input.empty() && !cmd.positionals.empty()) input = cmd.positionals[0];
  if (input.empty()) return fail(report, ExitCode::Usage, "missing --input");
  auto info = inspect_pe(input);
  if (!info) return fail(report, info.code(), info.message());
  report.summary = input.string();
  report_kv(report, "architecture", to_string(info.value().architecture));
  report_kv(report, "version", info.value().file_version.empty() ? "1.0.0.0"
                                                                : info.value().file_version);
  report_kv(report, "authenticode", info.value().authenticode_status);
  report_kv(report, "sha256", info.value().sha256);
  report_kv(report, "manifest", info.value().has_embedded_manifest ? "present" : "absent");
  if (!info.value().file_description.empty()) {
    report_kv(report, "description", info.value().file_description);
  }
  return finish(report, 0);
}

int op_patch_exe_identity(const ParsedCommand& cmd, Report& report) {
  const auto input = opt_path(cmd, "input");
  const auto name = cmd.require("name");
  const auto publisher = cmd.get("publisher").value_or(std::string(kUnsignedPublisher));
  const auto app_id = cmd.require("application-id");
  if (input.empty() || name.empty() || app_id.empty()) {
    return fail(report, ExitCode::Usage, "missing --input, --name, or --application-id");
  }
  PatchExeOptions opt;
  opt.identity.package_name = name;
  opt.identity.publisher = publisher;
  opt.identity.application_id = app_id;
  opt.accept_signature_loss = cmd.has_flag("accept-signature-loss");
  auto r = patch_exe_identity(input, opt);
  if (!r) return fail(report, r.code(), r.message());
  report.summary = "patched " + input.string();
  report_kv(report, "packageName", r.value().verified.package_name);
  report_kv(report, "publisher", r.value().verified.publisher);
  report_kv(report, "applicationId", r.value().verified.application_id);
  return finish(report, 0);
}

int op_make_manifest(const ParsedCommand& cmd, Report& report) {
  const auto layout_s = cmd.require("layout");
  const auto name = cmd.require("name");
  const auto exe = cmd.require("executable");
  const auto output = opt_path(cmd, "output");
  if (layout_s.empty() || name.empty() || exe.empty() || output.empty()) {
    return fail(report, ExitCode::Usage, "missing required options");
  }
  auto layout = parse_layout_kind(layout_s);
  if (!layout) return fail(report, layout.code(), layout.message());
  ManifestRequest req;
  req.layout = layout.value();
  req.identity.name = name;
  req.identity.publisher = cmd.get("publisher").value_or(std::string(kUnsignedPublisher));
  req.identity.version = cmd.get("version").value_or("1.0.0.0");
  if (auto a = cmd.get("architecture")) {
    auto p = parse_architecture(*a);
    if (!p) return fail(report, p.code(), p.message());
    req.identity.architecture = p.value();
  }
  req.application.executable = exe;
  req.application.id = cmd.get("application-id").value_or(sanitize_application_id(
      std::filesystem::path(exe).stem().string()));
  req.application.display_name = cmd.get("display-name").value_or(req.identity.name);
  if (cmd.has_flag("appcontainer")) {
    req.application.trust = TrustLevel::AppContainer;
    req.run_full_trust = false;
  }
  if (auto st = validate_identity(req.identity); !st) {
    return fail(report, st.code, st.message);
  }
  if (auto st = validate_application_id(req.application.id); !st) {
    return fail(report, st.code, st.message);
  }
  auto gen = generate_manifest(req);
  if (auto st = write_text(output, gen.xml); !st) return fail(report, st.code, st.message);
  report.summary = output.string();
  report_kv(report, "layout", to_string(req.layout));
  report_kv(report, "runtime", to_string(req.layout == LayoutKind::SparseExternal
                                            ? RuntimeBehavior::Win32App
                                            : RuntimeBehavior::PackagedClassicApp));
  return finish(report, 0);
}

int op_transform_msix_manifest(const ParsedCommand& cmd, Report& report) {
  const auto source = opt_path(cmd, "source");
  const auto name = cmd.require("name");
  const auto output = opt_path(cmd, "output");
  if (source.empty() || name.empty() || output.empty()) {
    return fail(report, ExitCode::Usage, "missing --source, --name, or --output");
  }
  auto doc = parse_xml(read_text(source));
  if (!doc) return fail(report, doc.code(), doc.message());
  ManifestRequest req;
  req.identity.name = name;
  req.identity.publisher = cmd.get("publisher").value_or(std::string(kUnsignedPublisher));
  req.identity.version = cmd.get("version").value_or("1.0.0.0");
  req.application.executable = cmd.get("executable").value_or("app.exe");
  req.application.id = cmd.get("application-id").value_or(sanitize_application_id(
      std::filesystem::path(req.application.executable).stem().string()));
  req.source_application_id = cmd.get("source-application-id").value_or("");
  req.application.display_name = cmd.get("display-name").value_or(name);
  ManifestValidator validator;
  auto makeappx = locate_makeappx_exe();
  if (makeappx) {
    validator = [&](std::string_view xml) {
      const auto tmp = output.parent_path() / ".repackager-validate";
      std::error_code ec;
      std::filesystem::create_directories(tmp / "Assets", ec);
      write_text(tmp / "AppxManifest.xml", xml);
      // Minimal placeholder assets so MakeAppx can see referenced logos.
      write_text(tmp / "Assets" / "StoreLogo.png", "x");
      write_text(tmp / "Assets" / "Square44x44Logo.png", "x");
      write_text(tmp / "Assets" / "Square150x150Logo.png", "x");
      auto st = validate_manifest_with_makeappx(tmp, makeappx.value(), true);
      std::filesystem::remove_all(tmp, ec);
      return st;
    };
  }
  auto tr = transform_msix_manifest_to_sparse(doc.value(), req, validator);
  if (!tr) return fail(report, tr.code(), tr.message());
  if (auto st = write_text(output, tr.value().xml); !st) {
    return fail(report, st.code, st.message);
  }
  report.summary = output.string();
  report_kv(report, "kept", std::to_string(tr.value().kept.size()));
  report_kv(report, "dropped", std::to_string(tr.value().dropped.size()));
  report.diagnostics = tr.value().warnings;
  return finish(report, 0);
}

int op_apply_manifest_overlay(const ParsedCommand& cmd, Report& report) {
  const auto manifest = opt_path(cmd, "manifest");
  const auto overlay = opt_path(cmd, "overlay");
  const auto output = opt_path(cmd, "output");
  if (manifest.empty() || overlay.empty() || output.empty()) {
    return fail(report, ExitCode::Usage, "missing --manifest, --overlay, or --output");
  }
  auto r = apply_manifest_overlay_text(read_text(manifest), read_text(overlay));
  if (!r) return fail(report, r.code(), r.message());
  if (auto st = write_text(output, serialize_xml(r.value().manifest, true)); !st) {
    return fail(report, st.code, st.message);
  }
  report.summary = output.string();
  report.diagnostics = r.value().warnings;
  return finish(report, 0);
}

int op_register_sparse(const ParsedCommand& cmd, Report& report) {
  RegistrationRequest req;
  req.manifest = opt_path(cmd, "manifest");
  req.external_location = opt_path(cmd, "external");
  req.sparse = true;
  if (req.manifest.empty() || req.external_location.empty()) {
    return fail(report, ExitCode::Usage, "missing --manifest or --external");
  }
  auto r = register_sparse(req);
  if (!r) return fail(report, r.code(), r.message());
  report.summary = r.value().package_full_name;
  report_kv(report, "family", r.value().package_family_name);
  report_kv(report, "aumid", r.value().aumid);
  return finish(report, 0);
}

int op_register_loose(const ParsedCommand& cmd, Report& report) {
  RegistrationRequest req;
  req.manifest = opt_path(cmd, "manifest");
  if (req.manifest.empty()) return fail(report, ExitCode::Usage, "missing --manifest");
  auto r = register_loose(req);
  if (!r) return fail(report, r.code(), r.message());
  report.summary = r.value().package_full_name;
  report_kv(report, "family", r.value().package_family_name);
  report_kv(report, "aumid", r.value().aumid);
  return finish(report, 0);
}

int op_activate(const ParsedCommand& cmd, Report& report) {
  const auto aumid = cmd.require("aumid");
  if (aumid.empty()) return fail(report, ExitCode::Usage, "missing --aumid");
  auto st = activate_aumid(aumid, cmd.get("arguments").value_or(""));
  if (!st) return fail(report, st.code, st.message);
  report.summary = aumid;
  return finish(report, 0);
}

int op_status(const ParsedCommand& cmd, Report& report) {
  auto name = cmd.require("name");
  if (name.empty() && !cmd.positionals.empty()) name = cmd.positionals[0];
  if (name.empty()) return fail(report, ExitCode::Usage, "missing --name");
  auto rec = load_authoritative_receipt(name);
  if (rec) {
    report_kv(report, "receipt", authoritative_receipt_path(name).string());
    report_kv(report, "fullName", rec.value().package_full_name);
    report_kv(report, "aumid", rec.value().aumid);
    report_kv(report, "layout", to_string(rec.value().layout));
    report_kv(report, "rollback", rec.value().rollback_status);
    if (!rec.value().package_full_name.empty()) {
      auto st = query_package_status(rec.value().package_full_name);
      if (st) report_kv(report, "registered", st.value().registered ? "yes" : "no");
    }
    report.summary = rec.value().package_full_name.empty() ? name : rec.value().package_full_name;
    return finish(report, 0);
  }
  auto st = query_package_status(name);
  if (!st) return fail(report, st.code(), st.message());
  report.summary = st.value().registered ? "registered" : "not-registered";
  report_kv(report, "fullName", st.value().package_full_name);
  return finish(report, 0);
}

int op_unregister(const ParsedCommand& cmd, Report& report) {
  const auto name = cmd.require("package-full-name");
  if (name.empty()) return fail(report, ExitCode::Usage, "missing --package-full-name");
  auto st = unregister_package(name);
  if (!st) return fail(report, st.code, st.message);
  report.summary = name;
  return finish(report, 0);
}

int op_remove_retrofit(const ParsedCommand& cmd, Report& report) {
  const auto name = cmd.require("name");
  if (name.empty()) return fail(report, ExitCode::Usage, "missing --name");
  Expected<Receipt> rec = cmd.get("receipt")
                              ? read_receipt_file(*cmd.get("receipt"))
                              : load_authoritative_receipt(name);
  if (!rec) return fail(report, rec.code(), rec.message());

  std::filesystem::path dir = rec.value().output_root.empty()
                                  ? std::filesystem::path(rec.value().source.path)
                                  : std::filesystem::path(rec.value().output_root);
  if (dir.empty() && !rec.value().created_paths.empty()) {
    dir = std::filesystem::path(rec.value().created_paths.front().path).parent_path();
  }
  if (!dir.empty() && needs_elevation_for_write(dir) && !process_is_elevated()) {
    ElevationRequest ereq;
    ereq.operation_id =
        rec.value().operation_id.empty() ? new_operation_id() : rec.value().operation_id;
    ereq.command = "remove-retrofit";
    ereq.directory = dir.string();
    ereq.args.push_back("--name");
    ereq.args.push_back(name);
    if (auto r = cmd.get("receipt")) {
      ereq.args.push_back("--receipt");
      ereq.args.push_back(*r);
    }
    if (auto r = cmd.get("report")) {
      ereq.args.push_back("--report");
      ereq.args.push_back(*r);
    }
    auto code = elevate_self_and_wait(ereq);
    if (!code) return fail(report, code.code(), code.message());
    return finish(report, code.value());
  }

  OperationJournal journal;
  journal.operation_id = rec.value().operation_id;
  journal.command = rec.value().command;
  journal.package_full_name = rec.value().package_full_name;
  if (!rec.value().package_full_name.empty()) {
    auto st = query_package_status(rec.value().package_full_name);
    journal.registered = st && st.value().registered;
  }
  for (const auto& p : rec.value().created_paths) journal.created_paths.push_back(p.path);

  RollbackHooks hooks;
  hooks.unregister = [](std::string_view full) { return unregister_package(full); };
  auto st = rollback_journal(journal, hooks);
  if (!st) return fail(report, st.code, st.message);

  rec.value().rollback_status = "complete";
  write_authoritative_receipt(rec.value());
  report.summary = "removed " + name;
  return finish(report, 0);
}

}  // namespace repackager
