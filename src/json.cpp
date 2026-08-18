#include "repackager/json.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace repackager {
namespace {

void skip_ws(std::string_view t, std::size_t& i) {
  while (i < t.size() && std::isspace(static_cast<unsigned char>(t[i]))) ++i;
}

Expected<Json> parse_value(std::string_view t, std::size_t& i);

Expected<std::string> parse_string(std::string_view t, std::size_t& i) {
  if (i >= t.size() || t[i] != '"') {
    return Expected<std::string>::fail(ExitCode::Validation, "expected string");
  }
  ++i;
  std::string out;
  while (i < t.size()) {
    char c = t[i++];
    if (c == '"') return Expected<std::string>::ok(std::move(out));
    if (c == '\\') {
      if (i >= t.size()) {
        return Expected<std::string>::fail(ExitCode::Validation, "bad escape");
      }
      char e = t[i++];
      switch (e) {
        case '"':
        case '\\':
        case '/':
          out.push_back(e);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u': {
          if (i + 4 > t.size()) {
            return Expected<std::string>::fail(ExitCode::Validation, "bad unicode escape");
          }
          unsigned cp = 0;
          for (int k = 0; k < 4; ++k) {
            char h = t[i++];
            cp <<= 4;
            if (h >= '0' && h <= '9') cp += static_cast<unsigned>(h - '0');
            else if (h >= 'a' && h <= 'f') cp += static_cast<unsigned>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') cp += static_cast<unsigned>(h - 'A' + 10);
            else {
              return Expected<std::string>::fail(ExitCode::Validation, "bad hex");
            }
          }
          if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
          } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          } else {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
          }
          break;
        }
        default:
          return Expected<std::string>::fail(ExitCode::Validation, "bad escape");
      }
    } else {
      out.push_back(c);
    }
  }
  return Expected<std::string>::fail(ExitCode::Validation, "unterminated string");
}

Expected<Json> parse_number(std::string_view t, std::size_t& i) {
  const std::size_t start = i;
  if (t[i] == '-') ++i;
  if (i >= t.size() || !std::isdigit(static_cast<unsigned char>(t[i]))) {
    return Expected<Json>::fail(ExitCode::Validation, "bad number");
  }
  while (i < t.size() && std::isdigit(static_cast<unsigned char>(t[i]))) ++i;
  if (i < t.size() && t[i] == '.') {
    ++i;
    while (i < t.size() && std::isdigit(static_cast<unsigned char>(t[i]))) ++i;
  }
  if (i < t.size() && (t[i] == 'e' || t[i] == 'E')) {
    ++i;
    if (i < t.size() && (t[i] == '+' || t[i] == '-')) ++i;
    while (i < t.size() && std::isdigit(static_cast<unsigned char>(t[i]))) ++i;
  }
  const double v = std::strtod(std::string(t.substr(start, i - start)).c_str(), nullptr);
  return Expected<Json>::ok(Json::number(v));
}

Expected<Json> parse_array(std::string_view t, std::size_t& i) {
  ++i;
  JsonArray arr;
  skip_ws(t, i);
  if (i < t.size() && t[i] == ']') {
    ++i;
    return Expected<Json>::ok(Json::array(std::move(arr)));
  }
  while (i < t.size()) {
    auto v = parse_value(t, i);
    if (!v) return v;
    arr.push_back(v.take());
    skip_ws(t, i);
    if (i < t.size() && t[i] == ',') {
      ++i;
      skip_ws(t, i);
      continue;
    }
    if (i < t.size() && t[i] == ']') {
      ++i;
      return Expected<Json>::ok(Json::array(std::move(arr)));
    }
    return Expected<Json>::fail(ExitCode::Validation, "expected ',' or ']'");
  }
  return Expected<Json>::fail(ExitCode::Validation, "unterminated array");
}

Expected<Json> parse_object(std::string_view t, std::size_t& i) {
  ++i;
  JsonObject obj;
  skip_ws(t, i);
  if (i < t.size() && t[i] == '}') {
    ++i;
    return Expected<Json>::ok(Json::object(std::move(obj)));
  }
  while (i < t.size()) {
    skip_ws(t, i);
    auto k = parse_string(t, i);
    if (!k) return Expected<Json>::fail(k.error());
    skip_ws(t, i);
    if (i >= t.size() || t[i] != ':') {
      return Expected<Json>::fail(ExitCode::Validation, "expected ':'");
    }
    ++i;
    auto v = parse_value(t, i);
    if (!v) return v;
    obj.emplace(k.take(), v.take());
    skip_ws(t, i);
    if (i < t.size() && t[i] == ',') {
      ++i;
      continue;
    }
    if (i < t.size() && t[i] == '}') {
      ++i;
      return Expected<Json>::ok(Json::object(std::move(obj)));
    }
    return Expected<Json>::fail(ExitCode::Validation, "expected ',' or '}'");
  }
  return Expected<Json>::fail(ExitCode::Validation, "unterminated object");
}

Expected<Json> parse_value(std::string_view t, std::size_t& i) {
  skip_ws(t, i);
  if (i >= t.size()) return Expected<Json>::fail(ExitCode::Validation, "unexpected end");
  const char c = t[i];
  if (c == '"') {
    auto s = parse_string(t, i);
    if (!s) return Expected<Json>::fail(s.error());
    return Expected<Json>::ok(Json::string(s.take()));
  }
  if (c == '{') return parse_object(t, i);
  if (c == '[') return parse_array(t, i);
  if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parse_number(t, i);
  if (t.substr(i, 4) == "true") {
    i += 4;
    return Expected<Json>::ok(Json::boolean(true));
  }
  if (t.substr(i, 5) == "false") {
    i += 5;
    return Expected<Json>::ok(Json::boolean(false));
  }
  if (t.substr(i, 4) == "null") {
    i += 4;
    return Expected<Json>::ok(Json::nul());
  }
  return Expected<Json>::fail(ExitCode::Validation, "invalid json value");
}

void dump(std::ostringstream& os, const Json& j, int indent, bool pretty) {
  auto pad = [&](int n) {
    if (pretty)
      for (int i = 0; i < n; ++i) os << "  ";
  };
  if (j.is_null()) {
    os << "null";
  } else if (j.is_bool()) {
    os << (j.as_bool() ? "true" : "false");
  } else if (j.is_number()) {
    const double d = j.as_number();
    if (std::floor(d) == d && std::abs(d) < 1e15) {
      os << static_cast<long long>(d);
    } else {
      os << d;
    }
  } else if (j.is_string()) {
    os << '"' << json_escape(j.as_string()) << '"';
  } else if (j.is_array()) {
    const auto& a = j.as_array();
    os << '[';
    if (pretty && !a.empty()) os << '\n';
    for (std::size_t i = 0; i < a.size(); ++i) {
      if (pretty) pad(indent + 1);
      dump(os, a[i], indent + 1, pretty);
      if (i + 1 < a.size()) os << ',';
      if (pretty) os << '\n';
    }
    if (pretty && !a.empty()) pad(indent);
    os << ']';
  } else {
    const auto& o = j.as_object();
    os << '{';
    if (pretty && !o.empty()) os << '\n';
    std::size_t i = 0;
    for (const auto& [k, v] : o) {
      if (pretty) pad(indent + 1);
      os << '"' << json_escape(k) << '"';
      os << (pretty ? ": " : ":");
      dump(os, v, indent + 1, pretty);
      if (i + 1 < o.size()) os << ',';
      if (pretty) os << '\n';
      ++i;
    }
    if (pretty && !o.empty()) pad(indent);
    os << '}';
  }
}

}  // namespace

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (unsigned char c : text) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

std::string serialize_json(const Json& value, bool pretty) {
  std::ostringstream os;
  dump(os, value, 0, pretty);
  if (pretty) os << '\n';
  return os.str();
}

Expected<Json> parse_json(std::string_view text) {
  std::size_t i = 0;
  auto v = parse_value(text, i);
  if (!v) return v;
  skip_ws(text, i);
  if (i != text.size()) {
    return Expected<Json>::fail(ExitCode::Validation, "trailing json content");
  }
  return v;
}

}  // namespace repackager
