#include "repackager/workflows.hpp"

#include "repackager/assets.hpp"
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
#include "repackager/xml.hpp"

#include <fstream>
#include <iostream>

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

int fail_msg(Report& report, ExitCode code, std::string message) {
  report.summary = std::move(message);
  return finish(report, static_cast<int>(code));
}

std::filesystem::path opt_path(const ParsedCommand& cmd, std::string_view key) {
  if (auto v = cmd.get(key)) return std::filesystem::path(*v);
  return {};
}

Status write_text(const std::filesystem::path& path, std::string_view text) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return Status::fail(ExitCode::Internal, "cannot write " + path.string());
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
  return Status::success();
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void record_created(Receipt& rec, OperationJournal& journal, const std::filesystem::path& path) {
  CreatedPath cp;
  cp.path = path.string();
  std::error_code ec;
  if (std::filesystem::is_regular_file(path, ec)) cp.sha256 = sha256_file_hex(path);
  rec.created_paths.push_back(cp);
  journal_record_path(journal, path);
}

Status copy_overlay_files(const std::filesystem::path& overlay_dir,
                          const std::filesystem::path& dest_root, Receipt& rec,
                          OperationJournal& journal) {
  if (overlay_dir.empty()) return Status::success();
  std::error_code ec;
  if (!std::filesystem::exists(overlay_dir, ec)) {
    return Status::fail(ExitCode::NotFound,
                        "overlay-files directory not found: " + overlay_dir.string());
  }
  for (auto it = std::filesystem::recursive_directory_iterator(overlay_dir, ec);
       it != std::filesystem::recursive_directory_iterator(); ++it) {
    if (!it->is_regular_file()) continue;
    const auto rel = std::filesystem::relative(it->path(), overlay_dir, ec);
    const auto dest = dest_root / rel;
    if (!path_contained(dest_root, dest)) {
      return Status::fail(ExitCode::Validation, "overlay file escapes destination");
    }
    if (std::filesystem::exists(dest, ec)) {
      return Status::fail(ExitCode::Conflict,
                          "overlay file collides with existing payload: " + dest.string());
    }
    std::filesystem::create_directories(dest.parent_path(), ec);
    std::filesystem::copy_file(it->path(), dest, ec);
    if (ec) return Status::fail(ExitCode::Internal, "overlay copy failed: " + ec.message());
    record_created(rec, journal, dest);
  }
  return Status::success();
}

Status apply_optional_overlay(const ParsedCommand& cmd, const std::filesystem::path& manifest_path,
                              Receipt& rec) {
  const auto overlay = opt_path(cmd, "overlay-manifest");
  if (overlay.empty()) return Status::success();
  auto r = apply_manifest_overlay_text(read_text(manifest_path), read_text(overlay));
  if (!r) return Status::fail(r.code(), r.message());
  rec.warnings.insert(rec.warnings.end(), r.value().warnings.begin(), r.value().warnings.end());
  return write_text(manifest_path, serialize_xml(r.value().manifest, true));
}

void persist_receipts(const Receipt& rec, const std::filesystem::path& layout_copy,
                      bool inplace, const std::filesystem::path& directory) {
  write_authoritative_receipt(rec);
  if (inplace) {
    write_receipt_file(inplace_receipt_path(directory, rec.identity.name), rec);
  } else if (!layout_copy.empty()) {
    write_receipt_file(layout_copy, rec);
  }
}

int rollback_and_fail(Report& report, Receipt& rec, OperationJournal& journal,
                      ExitCode code, std::string message) {
  RollbackHooks hooks;
  hooks.unregister = [](std::string_view full) { return unregister_package(full); };
  rollback_journal(journal, hooks);
  rec.rollback_status = "complete";
  write_authoritative_receipt(rec);
  report.diagnostics = rec.warnings;
  report.summary = std::move(message);
  return finish(report, static_cast<int>(code == ExitCode::Success ? ExitCode::RolledBack : code));
}

Status maybe_validate_makeappx(const std::filesystem::path& identity_dir, Report& report) {
  auto tool = locate_makeappx_exe();
  if (!tool) {
    report.diagnostics.push_back(Diagnostic{Diagnostic::Severity::Warning, "makeappx-missing",
                                            tool.message()});
    return Status::success();
  }
  return validate_manifest_with_makeappx(identity_dir, tool.value(), true);
}

}  // namespace

int workflow_retrofit_win32_sparse(const ParsedCommand& cmd, Report& report) {
  const auto source = opt_path(cmd, "source");
  const auto output = opt_path(cmd, "output");
  const auto name = cmd.require("name");
  const auto exe_arg = cmd.require("executable");
  if (source.empty() || output.empty() || name.empty() || exe_arg.empty()) {
    return fail_msg(report, ExitCode::Usage,
                    "require --source, --executable, --output, --name");
  }
  auto resolved = resolve_executable_under_root(source, exe_arg);
  if (!resolved) return fail_msg(report, resolved.code(), resolved.message());
  const auto rel_exe = resolved.value().relative;
  const auto source_exe = resolved.value().absolute;
  const auto manifest_exe = resolved.value().manifest;
  std::error_code ec;
  if (!directory_is_absent_or_empty(output)) {
    return fail_msg(report, ExitCode::Conflict, "output must be absent or empty");
  }
  if (auto st = validate_package_name(name); !st) {
    return fail_msg(report, st.code, st.message);
  }

  const auto source_hash = sha256_file_hex(source_exe);
  auto pe = inspect_pe(source_exe);
  if (!pe) return fail_msg(report, pe.code(), pe.message());

  Receipt rec;
  rec.operation_id = new_operation_id();
  rec.command = "retrofit-win32-sparse";
  rec.layout = LayoutKind::SparseExternal;
  rec.trust = TrustLevel::MediumIL;
  rec.identity.name = name;
  rec.identity.publisher = std::string(kUnsignedPublisher);
  rec.identity.version =
      pe.value().file_version.empty() ? "1.0.0.0" : pe.value().file_version;
  rec.identity.architecture = Architecture::Neutral;
  rec.application_id = cmd.get("application-id").value_or(
      sanitize_application_id(rel_exe.stem().string()));
  rec.identity = rec.identity;
  rec.source.kind = "win32-dir";
  rec.source.path = source.string();
  rec.output_root = output.string();
  rec.package_family_name = package_family_name(rec.identity);
  rec.package_full_name = package_full_name(rec.identity);
  rec.aumid = make_aumid(rec.package_family_name, rec.application_id);

  OperationJournal journal;
  journal.operation_id = rec.operation_id;
  journal.command = rec.command;
  const auto journal_path = output / ".repackager" / "journal.json";
  std::filesystem::create_directories(output / ".repackager", ec);
  journal.journal_path = journal_path.string();
  if (auto st = write_journal(journal_path, journal); !st) {
    return fail_msg(report, st.code, st.message);
  }
  record_created(rec, journal, journal_path);
  persist_receipts(rec, layout_receipt_path(output), false, {});

  if (auto st = fault_checkpoint("after-journal"); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }

  const auto payload = output / "payload";
  const auto identity_dir = output / "identity";
  const auto assets_dir = identity_dir / "Assets";
  StageOptions stage;
  stage.source = source;
  stage.destination = payload;
  auto staged = stage_files(stage, &journal);
  if (!staged) return rollback_and_fail(report, rec, journal, staged.code(), staged.message());
  for (const auto& c : staged.value().copied) rec.created_paths.push_back(c);

  const auto staged_exe = payload / rel_exe;
  PatchExeOptions patch;
  patch.identity.package_name = rec.identity.name;
  patch.identity.publisher = rec.identity.publisher;
  patch.identity.application_id = rec.application_id;
  patch.accept_signature_loss = cmd.has_flag("accept-signature-loss");
  auto patched = patch_exe_identity(staged_exe, patch);
  if (!patched) {
    return rollback_and_fail(report, rec, journal, patched.code(), patched.message());
  }

  auto assets = generate_assets(assets_dir, staged_exe, name, &journal);
  if (!assets) return rollback_and_fail(report, rec, journal, assets.code(), assets.message());
  rec.created_paths.insert(rec.created_paths.end(), assets.value().created.begin(),
                           assets.value().created.end());

  ManifestRequest mreq;
  mreq.layout = LayoutKind::SparseExternal;
  mreq.identity = rec.identity;
  mreq.application.id = rec.application_id;
  mreq.application.executable = manifest_exe;
  mreq.application.display_name = cmd.get("display-name").value_or(
      pe.value().file_description.empty()
          ? (pe.value().product_name.empty() ? name : pe.value().product_name)
          : pe.value().file_description);
  auto gen = generate_sparse_manifest(mreq);
  const auto manifest_path = identity_dir / "AppxManifest.xml";
  if (std::filesystem::exists(manifest_path, ec)) {
    return rollback_and_fail(report, rec, journal, ExitCode::Conflict,
                             "refusing to overwrite existing AppxManifest.xml");
  }
  if (auto st = write_text(manifest_path, gen.xml); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  record_created(rec, journal, manifest_path);

  if (auto st = apply_optional_overlay(cmd, manifest_path, rec); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  if (auto st = copy_overlay_files(opt_path(cmd, "overlay-files"), payload, rec, journal); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }

  if (auto st = maybe_validate_makeappx(identity_dir, report); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }

  rec.external_location = payload.string();
  persist_receipts(rec, layout_receipt_path(output), false, {});
  record_created(rec, journal, layout_receipt_path(output));

  const auto after_source = sha256_file_hex(source_exe);
  if (after_source != source_hash) {
    return rollback_and_fail(report, rec, journal, ExitCode::Internal,
                             "source executable was mutated");
  }

  if (!cmd.has_flag("prepare-only")) {
    RegistrationRequest req;
    req.manifest = manifest_path;
    req.external_location = payload;
    req.sparse = true;
    if (auto st = fault_checkpoint("before-register"); !st) {
      return rollback_and_fail(report, rec, journal, st.code, st.message);
    }
    auto reg = register_sparse(req);
    if (!reg) return rollback_and_fail(report, rec, journal, reg.code(), reg.message());
    rec.package_full_name = reg.value().package_full_name;
    rec.package_family_name = reg.value().package_family_name;
    rec.aumid = reg.value().aumid;
    journal.registered = true;
    journal.package_full_name = rec.package_full_name;
    write_journal(journal_path, journal);
    if (auto st = fault_checkpoint("after-register"); !st) {
      return rollback_and_fail(report, rec, journal, st.code, st.message);
    }
    auto st = query_package_status(rec.package_full_name);
    if (st && !st.value().registered) {
      rec.warnings.push_back(Diagnostic{Diagnostic::Severity::Warning, "status",
                                        "registration API succeeded but status query is empty"});
    }
    if (cmd.has_flag("launch")) {
      auto launched = launch_exe(staged_exe);
      rec.launch_result = launched ? "ok" : launched.message;
    }
  }

  persist_receipts(rec, layout_receipt_path(output), false, {});
  report.summary = rec.package_full_name;
  report_kv(report, "payload", payload.string());
  report_kv(report, "manifest", manifest_path.string());
  report_kv(report, "aumid", rec.aumid);
  report_kv(report, "family", rec.package_family_name);
  report_kv(report, "sourceSha256", source_hash);
  report.diagnostics = rec.warnings;
  return finish(report, 0);
}

int workflow_retrofit_win32_inplace(const ParsedCommand& cmd, Report& report) {
  const auto directory = opt_path(cmd, "directory");
  const auto name = cmd.require("name");
  const auto exe_arg = cmd.require("executable");
  if (directory.empty() || name.empty() || exe_arg.empty()) {
    return fail_msg(report, ExitCode::Usage, "require --directory, --executable, --name");
  }
  auto resolved = resolve_executable_under_root(directory, exe_arg);
  if (!resolved) return fail_msg(report, resolved.code(), resolved.message());
  const auto rel_exe = resolved.value().relative;
  const auto exe = resolved.value().absolute;
  const auto manifest_exe = resolved.value().manifest;
  std::error_code ec;
  if (std::filesystem::exists(directory / "AppxManifest.xml", ec)) {
    return fail_msg(report, ExitCode::Conflict, "directory already contains AppxManifest.xml");
  }
  if (std::filesystem::exists(inplace_receipt_path(directory, name), ec) ||
      std::filesystem::exists(directory / "RepackagerAssets", ec)) {
    return fail_msg(report, ExitCode::Conflict, "colliding tool-owned paths already exist");
  }
  if (auto st = validate_package_name(name); !st) {
    return fail_msg(report, st.code, st.message);
  }

  const auto source_hash = sha256_file_hex(exe);
  auto pe = inspect_pe(exe);
  if (!pe) return fail_msg(report, pe.code(), pe.message());

  const bool elevate = needs_elevation_for_write(directory) && !process_is_elevated();
  if (elevate) {
    ElevationRequest ereq;
    ereq.operation_id = new_operation_id();
    ereq.command = "retrofit-win32-inplace";
    ereq.directory = directory.string();
    ereq.expected_exe_path = exe.string();
    ereq.expected_exe_sha256 = source_hash;
    for (const auto& [k, v] : cmd.options) {
      ereq.args.push_back("--" + k);
      ereq.args.push_back(v);
    }
    for (const auto& f : cmd.flags) ereq.args.push_back("--" + f);
    auto code = elevate_self_and_wait(ereq);
    if (!code) return fail_msg(report, code.code(), code.message());
    return finish(report, code.value());
  }

  Receipt rec;
  rec.operation_id = new_operation_id();
  rec.command = "retrofit-win32-inplace";
  rec.layout = LayoutKind::LooseFull;
  rec.trust = cmd.has_flag("appcontainer") ? TrustLevel::AppContainer : TrustLevel::MediumIL;
  rec.elevated = process_is_elevated();
  rec.identity.name = name;
  rec.identity.publisher = std::string(kUnsignedPublisher);
  rec.identity.version =
      pe.value().file_version.empty() ? "1.0.0.0" : pe.value().file_version;
  rec.identity.architecture = pe.value().architecture;
  rec.application_id = cmd.get("application-id").value_or(
      sanitize_application_id(rel_exe.stem().string()));
  rec.source.kind = "win32-inplace";
  rec.source.path = directory.string();
  rec.output_root = directory.string();
  rec.package_family_name = package_family_name(rec.identity);
  rec.package_full_name = package_full_name(rec.identity);
  rec.aumid = make_aumid(rec.package_family_name, rec.application_id);
  if (cmd.has_flag("appcontainer")) {
    rec.warnings.push_back(Diagnostic{
        Diagnostic::Severity::Warning, "appcontainer",
        "AppContainer mode omits runFullTrust; many classic Win32 apps will not run correctly"});
  }

  OperationJournal journal;
  journal.operation_id = rec.operation_id;
  journal.command = rec.command;
  const auto journal_path = default_data_root() / "journals" / (rec.operation_id + ".json");
  journal.journal_path = journal_path.string();
  write_journal(journal_path, journal);
  persist_receipts(rec, {}, true, directory);

  const auto assets_root = directory / "RepackagerAssets";
  const auto assets_dir = assets_root / rec.operation_id;
  // Journal the directory first so reverse rollback deletes files then the dir
  // (and remove_all still works if children remain).
  std::filesystem::create_directories(assets_dir, ec);
  record_created(rec, journal, assets_root);
  record_created(rec, journal, assets_dir);
  auto assets = generate_assets(assets_dir, exe, name, &journal);
  if (!assets) return rollback_and_fail(report, rec, journal, assets.code(), assets.message());
  rec.created_paths.insert(rec.created_paths.end(), assets.value().created.begin(),
                           assets.value().created.end());

  ManifestRequest mreq;
  mreq.layout = LayoutKind::LooseFull;
  mreq.identity = rec.identity;
  mreq.application.id = rec.application_id;
  mreq.application.executable = manifest_exe;
  mreq.application.trust = rec.trust;
  mreq.application.display_name = cmd.get("display-name").value_or(
      pe.value().file_description.empty() ? name : pe.value().file_description);
  mreq.logo = win_relative_path(std::filesystem::path("RepackagerAssets") / rec.operation_id /
                                "StoreLogo.png");
  mreq.square44 = win_relative_path(std::filesystem::path("RepackagerAssets") / rec.operation_id /
                                    "Square44x44Logo.png");
  mreq.square150 = win_relative_path(std::filesystem::path("RepackagerAssets") / rec.operation_id /
                                     "Square150x150Logo.png");
  auto gen = generate_loose_manifest(mreq);
  const auto manifest_path = directory / "AppxManifest.xml";
  if (auto st = write_text(manifest_path, gen.xml); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  record_created(rec, journal, manifest_path);

  if (auto st = apply_optional_overlay(cmd, manifest_path, rec); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  if (auto st = copy_overlay_files(opt_path(cmd, "overlay-files"), directory, rec, journal); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }

  const auto receipt_copy = inplace_receipt_path(directory, name);
  persist_receipts(rec, {}, true, directory);
  record_created(rec, journal, receipt_copy);

  if (sha256_file_hex(exe) != source_hash) {
    return rollback_and_fail(report, rec, journal, ExitCode::Internal,
                             "in-place workflow mutated the executable");
  }

  if (!cmd.has_flag("prepare-only")) {
    RegistrationRequest req;
    req.manifest = manifest_path;
    auto reg = register_loose(req);
    if (!reg) return rollback_and_fail(report, rec, journal, reg.code(), reg.message());
    rec.package_full_name = reg.value().package_full_name;
    rec.package_family_name = reg.value().package_family_name;
    rec.aumid = reg.value().aumid;
    journal.registered = true;
    journal.package_full_name = rec.package_full_name;
    write_journal(journal_path, journal);
    if (cmd.has_flag("launch")) {
      auto launched = activate_aumid(rec.aumid);
      rec.launch_result = launched ? "ok" : launched.message;
    }
  }

  // After RegisterPackageByUriAsync the directory is the package. Rewriting the
  // namespaced receipt (or any other file) there marks the package Modified and
  // Windows shows the Repair dialog on launch. Post-register updates go only to
  // the LOCALAPPDATA authoritative receipt.
  write_authoritative_receipt(rec);
  if (!cmd.has_flag("prepare-only") && !rec.package_full_name.empty()) {
    auto st = query_package_status(rec.package_full_name);
    if (st && st.value().registered &&
        (st.value().needs_remediation || st.value().modified || !st.value().ok)) {
      return rollback_and_fail(
          report, rec, journal, ExitCode::Environment,
          "registered loose package needs remediation (payload modified after register)");
    }
  }
  report.summary = rec.package_full_name;
  report_kv(report, "manifest", manifest_path.string());
  report_kv(report, "aumid", rec.aumid);
  report_kv(report, "exeSha256", source_hash);
  report.diagnostics = rec.warnings;
  return finish(report, 0);
}

int workflow_retrofit_msix_sparse(const ParsedCommand& cmd, Report& report) {
  const auto full = cmd.require("package-full-name");
  const auto output = opt_path(cmd, "output");
  const auto name = cmd.require("name");
  if (full.empty() || output.empty() || name.empty()) {
    return fail_msg(report, ExitCode::Usage,
                    "require --package-full-name, --output, --name");
  }
  if (!directory_is_absent_or_empty(output)) {
    return fail_msg(report, ExitCode::Conflict, "output must be absent or empty");
  }
  if (auto st = validate_package_name(name); !st) {
    return fail_msg(report, st.code, st.message);
  }

  auto installed = find_installed_package(full);
  if (!installed) return fail_msg(report, installed.code(), installed.message());
  if (installed.value().is_framework || installed.value().is_resource ||
      installed.value().is_optional) {
    return fail_msg(report, ExitCode::Validation,
                    "only main packages can be converted (not framework/resource/optional)");
  }
  const auto installed_loc = std::filesystem::path(installed.value().installed_location);
  const auto src_manifest = installed_loc / "AppxManifest.xml";
  std::error_code ec;
  if (!std::filesystem::exists(src_manifest, ec)) {
    return fail_msg(report, ExitCode::Validation,
                    "installed package has no readable AppxManifest.xml (encrypted or inaccessible)");
  }

  auto src_doc = parse_xml(read_text(src_manifest));
  if (!src_doc) return fail_msg(report, src_doc.code(), src_doc.message());

  std::vector<ApplicationDeclaration> apps;
  if (const auto* apps_n = src_doc.value().root.find_child("Applications")) {
    for (const auto& a : apps_n->children) {
      if (a.name != "Application") continue;
      ApplicationDeclaration d;
      d.id = a.attr("Id");
      d.executable = a.attr("Executable");
      apps.push_back(d);
    }
  }
  std::string source_app_id = cmd.get("source-application-id").value_or("");
  if (apps.size() != 1 && source_app_id.empty()) {
    return fail_msg(report, ExitCode::Usage,
                    "package has multiple applications; pass --source-application-id");
  }
  if (apps.size() == 1 && source_app_id.empty()) source_app_id = apps.front().id;
  ApplicationDeclaration selected;
  for (const auto& a : apps) {
    if (a.id == source_app_id) selected = a;
  }
  if (selected.id.empty()) {
    return fail_msg(report, ExitCode::NotFound, "source application id not found");
  }

  Receipt rec;
  rec.operation_id = new_operation_id();
  rec.command = "retrofit-msix-sparse";
  rec.layout = LayoutKind::SparseExternal;
  rec.trust = TrustLevel::MediumIL;
  rec.identity.name = name;
  rec.identity.publisher = std::string(kUnsignedPublisher);
  rec.identity.version = installed.value().version.empty() ? "1.0.0.0" : installed.value().version;
  rec.identity.architecture = Architecture::Neutral;
  rec.application_id = cmd.get("application-id").value_or(sanitize_application_id(selected.id));
  rec.source.kind = "installed-msix";
  rec.source.path = installed_loc.string();
  rec.source.package_full_name = full;
  rec.source.source_application_id = source_app_id;
  rec.source.reported_dependencies = installed.value().dependencies;
  rec.output_root = output.string();
  rec.package_family_name = package_family_name(rec.identity);
  rec.package_full_name = package_full_name(rec.identity);
  rec.aumid = make_aumid(rec.package_family_name, rec.application_id);
  for (const auto& dep : installed.value().dependencies) {
    rec.warnings.push_back(Diagnostic{Diagnostic::Severity::Info, "dependency",
                                      "source depends on " + dep + " (not cloned)"});
  }

  OperationJournal journal;
  journal.operation_id = rec.operation_id;
  journal.command = rec.command;
  const auto journal_path = output / ".repackager" / "journal.json";
  std::filesystem::create_directories(output / ".repackager", ec);
  journal.journal_path = journal_path.string();
  write_journal(journal_path, journal);
  record_created(rec, journal, journal_path);
  persist_receipts(rec, layout_receipt_path(output), false, {});

  const auto payload = output / "payload";
  const auto identity_dir = output / "identity";
  StageOptions stage;
  stage.source = installed_loc;
  stage.destination = payload;
  stage.exclude_names = default_msix_footprint_excludes();
  auto staged = stage_files(stage, &journal);
  if (!staged) return rollback_and_fail(report, rec, journal, staged.code(), staged.message());
  for (const auto& c : staged.value().copied) rec.created_paths.push_back(c);

  const auto staged_exe = payload / selected.executable;
  if (!std::filesystem::exists(staged_exe, ec)) {
    return rollback_and_fail(report, rec, journal, ExitCode::NotFound,
                             "selected executable missing from copied payload");
  }
  PatchExeOptions patch;
  patch.identity.package_name = rec.identity.name;
  patch.identity.publisher = rec.identity.publisher;
  patch.identity.application_id = rec.application_id;
  patch.accept_signature_loss = cmd.has_flag("accept-signature-loss");
  auto patched = patch_exe_identity(staged_exe, patch);
  if (!patched) {
    return rollback_and_fail(report, rec, journal, patched.code(), patched.message());
  }

  auto assets = generate_assets(identity_dir / "Assets", staged_exe, name, &journal);
  if (!assets) return rollback_and_fail(report, rec, journal, assets.code(), assets.message());

  ManifestRequest mreq;
  mreq.layout = LayoutKind::SparseExternal;
  mreq.identity = rec.identity;
  mreq.application.id = rec.application_id;
  mreq.application.executable = win_relative_path(selected.executable);
  if (auto st = validate_package_relative_executable(mreq.application.executable); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  mreq.source_application_id = source_app_id;
  mreq.application.display_name = cmd.get("display-name").value_or(
      selected.display_name.empty() ? name : selected.display_name);

  ManifestValidator validator;
  auto makeappx = locate_makeappx_exe();
  if (makeappx) {
    validator = [&](std::string_view xml) {
      const auto tmp = output / ".repackager-validate";
      std::error_code ec2;
      std::filesystem::create_directories(tmp / "Assets", ec2);
      write_text(tmp / "AppxManifest.xml", xml);
      std::filesystem::copy_file(identity_dir / "Assets" / "StoreLogo.png",
                                 tmp / "Assets" / "StoreLogo.png",
                                 std::filesystem::copy_options::overwrite_existing, ec2);
      std::filesystem::copy_file(identity_dir / "Assets" / "Square44x44Logo.png",
                                 tmp / "Assets" / "Square44x44Logo.png",
                                 std::filesystem::copy_options::overwrite_existing, ec2);
      std::filesystem::copy_file(identity_dir / "Assets" / "Square150x150Logo.png",
                                 tmp / "Assets" / "Square150x150Logo.png",
                                 std::filesystem::copy_options::overwrite_existing, ec2);
      auto st = validate_manifest_with_makeappx(tmp, makeappx.value(), true);
      std::filesystem::remove_all(tmp, ec2);
      return st;
    };
  }
  auto tr = transform_msix_manifest_to_sparse(src_doc.value(), mreq, validator);
  if (!tr) return rollback_and_fail(report, rec, journal, tr.code(), tr.message());
  rec.warnings.insert(rec.warnings.end(), tr.value().warnings.begin(), tr.value().warnings.end());

  const auto manifest_path = identity_dir / "AppxManifest.xml";
  if (auto st = write_text(manifest_path, tr.value().xml); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  record_created(rec, journal, manifest_path);

  if (auto st = apply_optional_overlay(cmd, manifest_path, rec); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }
  if (auto st = copy_overlay_files(opt_path(cmd, "overlay-files"), payload, rec, journal); !st) {
    return rollback_and_fail(report, rec, journal, st.code, st.message);
  }

  rec.external_location = payload.string();
  persist_receipts(rec, layout_receipt_path(output), false, {});

  if (!cmd.has_flag("prepare-only")) {
    RegistrationRequest req;
    req.manifest = manifest_path;
    req.external_location = payload;
    req.sparse = true;
    auto reg = register_sparse(req);
    if (!reg) return rollback_and_fail(report, rec, journal, reg.code(), reg.message());
    rec.package_full_name = reg.value().package_full_name;
    rec.package_family_name = reg.value().package_family_name;
    rec.aumid = reg.value().aumid;
    journal.registered = true;
    journal.package_full_name = rec.package_full_name;
    write_journal(journal_path, journal);
    if (cmd.has_flag("launch")) {
      auto launched = launch_exe(staged_exe);
      rec.launch_result = launched ? "ok" : launched.message;
    }
  }

  persist_receipts(rec, layout_receipt_path(output), false, {});
  report.summary = rec.package_full_name;
  report_kv(report, "source", full);
  report_kv(report, "kept", std::to_string(tr.value().kept.size()));
  report_kv(report, "dropped", std::to_string(tr.value().dropped.size()));
  report_kv(report, "aumid", rec.aumid);
  report.diagnostics = rec.warnings;
  return finish(report, 0);
}

}  // namespace repackager
