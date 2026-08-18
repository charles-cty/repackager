#pragma once

#include "repackager/error.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace repackager {

struct Json;
using JsonObject = std::map<std::string, Json>;
using JsonArray = std::vector<Json>;

struct Json {
  std::variant<std::nullptr_t, bool, double, std::string, JsonArray, JsonObject> v;

  static Json nul() { return Json{nullptr}; }
  static Json boolean(bool b) { return Json{b}; }
  static Json number(double d) { return Json{d}; }
  static Json number(int i) { return Json{static_cast<double>(i)}; }
  static Json string(std::string s) { return Json{std::move(s)}; }
  static Json array(JsonArray a = {}) { return Json{std::move(a)}; }
  static Json object(JsonObject o = {}) { return Json{std::move(o)}; }

  bool is_null() const { return std::holds_alternative<std::nullptr_t>(v); }
  bool is_bool() const { return std::holds_alternative<bool>(v); }
  bool is_number() const { return std::holds_alternative<double>(v); }
  bool is_string() const { return std::holds_alternative<std::string>(v); }
  bool is_array() const { return std::holds_alternative<JsonArray>(v); }
  bool is_object() const { return std::holds_alternative<JsonObject>(v); }

  bool as_bool(bool fallback = false) const {
    return is_bool() ? std::get<bool>(v) : fallback;
  }
  double as_number(double fallback = 0) const {
    return is_number() ? std::get<double>(v) : fallback;
  }
  int as_int(int fallback = 0) const {
    return static_cast<int>(as_number(fallback));
  }
  const std::string& as_string() const {
    static const std::string empty;
    return is_string() ? std::get<std::string>(v) : empty;
  }
  std::string as_string(std::string fallback) const {
    return is_string() ? std::get<std::string>(v) : std::move(fallback);
  }
  const JsonArray& as_array() const {
    static const JsonArray empty;
    return is_array() ? std::get<JsonArray>(v) : empty;
  }
  const JsonObject& as_object() const {
    static const JsonObject empty;
    return is_object() ? std::get<JsonObject>(v) : empty;
  }
  JsonArray& as_array_mut() { return std::get<JsonArray>(v); }
  JsonObject& as_object_mut() { return std::get<JsonObject>(v); }

  const Json* get(std::string_view key) const {
    if (!is_object()) return nullptr;
    auto it = std::get<JsonObject>(v).find(std::string(key));
    return it == std::get<JsonObject>(v).end() ? nullptr : &it->second;
  }
  std::string get_string(std::string_view key, std::string fallback = {}) const {
    const Json* j = get(key);
    return j ? j->as_string(std::move(fallback)) : fallback;
  }
  bool get_bool(std::string_view key, bool fallback = false) const {
    const Json* j = get(key);
    return j ? j->as_bool(fallback) : fallback;
  }
  int get_int(std::string_view key, int fallback = 0) const {
    const Json* j = get(key);
    return j ? j->as_int(fallback) : fallback;
  }
};

std::string json_escape(std::string_view text);
std::string serialize_json(const Json& value, bool pretty = true);
Expected<Json> parse_json(std::string_view text);

}  // namespace repackager
