#include "repackager/receipt.hpp"

#include "repackager/hash.hpp"
#include "repackager/identity.hpp"
#include "repackager/paths.hpp"

#include <fstream>
#include <sstream>

namespace repackager {
namespace {

Json identity_json(const PackageIdentity& id) {
  JsonObject o;
  o["name"] = Json::string(id.name);
  o["publisher"] = Json::string(id.publisher);
  o["version"] = Json::string(id.version);
  o["architecture"] = Json::string(std::string(to_string(id.architecture)));
  if (!id.resource_id.empty()) o["resourceId"] = Json::string(id.resource_id);
  return Json::object(std::move(o));
}

Expected<PackageIdentity> identity_from(const Json& j) {
  PackageIdentity id;
  id.name = j.get_string("name");
  id.publisher = j.get_string("publisher", std::string(kUnsignedPublisher));
  id.version = j.get_string("version", "1.0.0.0");
  id.resource_id = j.get_string("resourceId");
  if (const auto* a = j.get("architecture")) {
    auto p = parse_architecture(a->as_string());
    if (!p) return Expected<PackageIdentity>::fail(p.error());
    id.architecture = p.value();
  }
  return Expected<PackageIdentity>::ok(std::move(id));
}

Json source_json(const SourceMetadata& s) {
  JsonObject o;
  o["kind"] = Json::string(s.kind);
  o["path"] = Json::string(s.path);
  o["packageFullName"] = Json::string(s.package_full_name);
  o["sourceApplicationId"] = Json::string(s.source_application_id);
  JsonArray deps;
  for (const auto& d : s.reported_dependencies) deps.push_back(Json::string(d));
  o["reportedDependencies"] = Json::array(std::move(deps));
  return Json::object(std::move(o));
}

SourceMetadata source_from(const Json& j) {
  SourceMetadata s;
  s.kind = j.get_string("kind");
  s.path = j.get_string("path");
  s.package_full_name = j.get_string("packageFullName");
  s.source_application_id = j.get_string("sourceApplicationId");
  if (const auto* d = j.get("reportedDependencies"); d && d->is_array()) {
    for (const auto& x : d->as_array()) s.reported_dependencies.push_back(x.as_string());
  }
  return s;
}

bool write_all(const std::filesystem::path& path, std::string_view text) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  const auto tmp = path.string() + ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) return false;
  }
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(path, ec);
    std::filesystem::rename(tmp, path, ec);
    if (ec) return false;
  }
  return true;
}

}  // namespace

Json receipt_to_json(const Receipt& r) {
  JsonObject o;
  o["schemaVersion"] = Json::number(r.schema_version);
  o["operationId"] = Json::string(r.operation_id);
  o["command"] = Json::string(r.command);
  o["identity"] = identity_json(r.identity);
  o["layout"] = Json::string(std::string(to_string(r.layout)));
  o["trustLevel"] = Json::string(std::string(to_string(r.trust)));
  o["packageFullName"] = Json::string(r.package_full_name);
  o["packageFamilyName"] = Json::string(r.package_family_name);
  o["applicationId"] = Json::string(r.application_id);
  o["aumid"] = Json::string(r.aumid);
  JsonArray created;
  for (const auto& c : r.created_paths) {
    JsonObject p;
    p["path"] = Json::string(c.path);
    p["sha256"] = Json::string(c.sha256);
    created.push_back(Json::object(std::move(p)));
  }
  o["createdPaths"] = Json::array(std::move(created));
  JsonArray warns;
  for (const auto& w : r.warnings) {
    JsonObject p;
    p["severity"] = Json::string(w.severity == Diagnostic::Severity::Error
                                     ? "error"
                                     : w.severity == Diagnostic::Severity::Info ? "info"
                                                                               : "warning");
    p["code"] = Json::string(w.code);
    p["message"] = Json::string(w.message);
    warns.push_back(Json::object(std::move(p)));
  }
  o["warnings"] = Json::array(std::move(warns));
  o["elevated"] = Json::boolean(r.elevated);
  o["rollbackStatus"] = Json::string(r.rollback_status);
  o["source"] = source_json(r.source);
  o["launchResult"] = Json::string(r.launch_result);
  o["outputRoot"] = Json::string(r.output_root);
  o["externalLocation"] = Json::string(r.external_location);
  return Json::object(std::move(o));
}

Expected<Receipt> receipt_from_json(const Json& json) {
  if (!json.is_object()) {
    return Expected<Receipt>::fail(ExitCode::Validation, "receipt is not an object");
  }
  Receipt r;
  r.schema_version = json.get_int("schemaVersion", 1);
  r.operation_id = json.get_string("operationId");
  r.command = json.get_string("command");
  if (const auto* id = json.get("identity")) {
    auto parsed = identity_from(*id);
    if (!parsed) return Expected<Receipt>::fail(parsed.error());
    r.identity = parsed.take();
  }
  if (const auto* l = json.get("layout")) {
    auto p = parse_layout_kind(l->as_string());
    if (!p) return Expected<Receipt>::fail(p.error());
    r.layout = p.value();
  }
  if (const auto* t = json.get("trustLevel")) {
    auto p = parse_trust_level(t->as_string());
    if (!p) return Expected<Receipt>::fail(p.error());
    r.trust = p.value();
  }
  r.package_full_name = json.get_string("packageFullName");
  r.package_family_name = json.get_string("packageFamilyName");
  r.application_id = json.get_string("applicationId");
  r.aumid = json.get_string("aumid");
  if (const auto* c = json.get("createdPaths"); c && c->is_array()) {
    for (const auto& x : c->as_array()) {
      r.created_paths.push_back(CreatedPath{x.get_string("path"), x.get_string("sha256")});
    }
  }
  if (const auto* w = json.get("warnings"); w && w->is_array()) {
    for (const auto& x : w->as_array()) {
      Diagnostic d;
      const auto sev = x.get_string("severity", "warning");
      d.severity = sev == "error"   ? Diagnostic::Severity::Error
                   : sev == "info"  ? Diagnostic::Severity::Info
                                    : Diagnostic::Severity::Warning;
      d.code = x.get_string("code");
      d.message = x.get_string("message");
      r.warnings.push_back(std::move(d));
    }
  }
  r.elevated = json.get_bool("elevated", false);
  r.rollback_status = json.get_string("rollbackStatus", "none");
  if (const auto* s = json.get("source")) r.source = source_from(*s);
  r.launch_result = json.get_string("launchResult");
  r.output_root = json.get_string("outputRoot");
  r.external_location = json.get_string("externalLocation");
  return Expected<Receipt>::ok(std::move(r));
}

std::string serialize_receipt(const Receipt& receipt) {
  return serialize_json(receipt_to_json(receipt), true);
}

Expected<Receipt> parse_receipt(std::string_view text) {
  auto j = parse_json(text);
  if (!j) return Expected<Receipt>::fail(j.error());
  return receipt_from_json(j.value());
}

Status write_receipt_file(const std::filesystem::path& path, const Receipt& receipt) {
  if (!write_all(path, serialize_receipt(receipt))) {
    return Status::fail(ExitCode::Internal, "failed to write receipt: " + path.string());
  }
  return Status::success();
}

Expected<Receipt> read_receipt_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return Expected<Receipt>::fail(ExitCode::NotFound,
                                   "receipt not found: " + path.string());
  }
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return parse_receipt(text);
}

std::filesystem::path authoritative_receipt_path(std::string_view package_name) {
  return receipt_dir_for(package_name) / "receipt.json";
}

Status write_authoritative_receipt(const Receipt& receipt) {
  return write_receipt_file(authoritative_receipt_path(receipt.identity.name), receipt);
}

Expected<Receipt> load_authoritative_receipt(std::string_view package_name) {
  return read_receipt_file(authoritative_receipt_path(package_name));
}

std::filesystem::path layout_receipt_path(const std::filesystem::path& output_root) {
  return output_root / ".repackager" / "receipt.json";
}

std::filesystem::path inplace_receipt_path(const std::filesystem::path& directory,
                                           std::string_view package_name) {
  return directory / (".repackager-" + std::string(package_name) + ".receipt.json");
}

}  // namespace repackager
