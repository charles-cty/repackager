#include "repackager/xml.hpp"

#include <cctype>
#include <cstdlib>
#include <map>
#include <sstream>

namespace repackager {
namespace {

struct NsScope {
  std::map<std::string, std::string> prefix_to_uri;
  std::string default_ns;
};

std::string_view ltrim(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
  return s;
}

bool starts_with(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

std::string unescape(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '&') {
      out.push_back(s[i]);
      continue;
    }
    const auto semi = s.find(';', i);
    if (semi == std::string_view::npos) {
      out.push_back('&');
      continue;
    }
    const auto ent = s.substr(i + 1, semi - i - 1);
    if (ent == "lt") out.push_back('<');
    else if (ent == "gt") out.push_back('>');
    else if (ent == "amp") out.push_back('&');
    else if (ent == "quot") out.push_back('"');
    else if (ent == "apos") out.push_back('\'');
    else if (!ent.empty() && ent[0] == '#') {
      unsigned long cp = 0;
      if (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')) {
        cp = std::strtoul(std::string(ent.substr(2)).c_str(), nullptr, 16);
      } else {
        cp = std::strtoul(std::string(ent.substr(1)).c_str(), nullptr, 10);
      }
      if (cp < 0x80) out.push_back(static_cast<char>(cp));
      else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
      } else {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
      }
    } else {
      out.append("&").append(ent).append(";");
    }
    i = semi;
  }
  return out;
}

struct Parser {
  std::string_view text;
  std::size_t pos = 0;

  bool eof() const { return pos >= text.size(); }
  char peek() const { return eof() ? '\0' : text[pos]; }
  char get() { return eof() ? '\0' : text[pos++]; }

  void skip_ws() {
    while (!eof() && std::isspace(static_cast<unsigned char>(peek()))) ++pos;
  }

  bool consume(std::string_view lit) {
    if (starts_with(text.substr(pos), lit)) {
      pos += lit.size();
      return true;
    }
    return false;
  }

  Expected<std::string> parse_name() {
    const std::size_t start = pos;
    if (eof()) return Expected<std::string>::fail(ExitCode::Validation, "expected name");
    const unsigned char c = static_cast<unsigned char>(peek());
    if (!(std::isalpha(c) || c == '_' || c == ':')) {
      return Expected<std::string>::fail(ExitCode::Validation, "invalid name start");
    }
    ++pos;
    while (!eof()) {
      const unsigned char n = static_cast<unsigned char>(peek());
      if (std::isalnum(n) || n == '_' || n == '-' || n == '.' || n == ':') {
        ++pos;
      } else {
        break;
      }
    }
    return Expected<std::string>::ok(std::string(text.substr(start, pos - start)));
  }

  Expected<std::string> parse_quoted() {
    const char q = get();
    if (q != '"' && q != '\'') {
      return Expected<std::string>::fail(ExitCode::Validation, "expected quoted value");
    }
    const std::size_t start = pos;
    while (!eof() && peek() != q) ++pos;
    if (eof()) return Expected<std::string>::fail(ExitCode::Validation, "unterminated string");
    auto raw = text.substr(start, pos - start);
    ++pos;
    return Expected<std::string>::ok(unescape(raw));
  }

  void skip_comment_or_pi_or_doctype() {
    if (consume("<!--")) {
      const auto end = text.find("-->", pos);
      pos = end == std::string_view::npos ? text.size() : end + 3;
      return;
    }
    if (consume("<?")) {
      const auto end = text.find("?>", pos);
      pos = end == std::string_view::npos ? text.size() : end + 2;
      return;
    }
    if (consume("<!DOCTYPE") || consume("<!doctype")) {
      int depth = 1;
      while (!eof() && depth) {
        if (peek() == '<') ++depth;
        else if (peek() == '>') --depth;
        ++pos;
      }
      return;
    }
    if (consume("<![CDATA[")) {
      const auto end = text.find("]]>", pos);
      pos = end == std::string_view::npos ? text.size() : end + 3;
    }
  }

  Expected<XmlNode> parse_element(const NsScope& parent) {
    if (!consume("<")) {
      return Expected<XmlNode>::fail(ExitCode::Validation, "expected '<'");
    }
    auto name_e = parse_name();
    if (!name_e) return Expected<XmlNode>::fail(name_e.error());
    XmlNode node;
    const std::string qname = name_e.take();
    const auto colon = qname.find(':');
    if (colon != std::string::npos) {
      node.prefix = qname.substr(0, colon);
      node.name = qname.substr(colon + 1);
    } else {
      node.name = qname;
    }

    NsScope scope = parent;
    skip_ws();
    while (!eof() && peek() != '>' && peek() != '/') {
      auto an_e = parse_name();
      if (!an_e) return Expected<XmlNode>::fail(an_e.error());
      const std::string an = an_e.take();
      skip_ws();
      if (!consume("=")) {
        return Expected<XmlNode>::fail(ExitCode::Validation, "expected '=' in attribute");
      }
      skip_ws();
      auto av_e = parse_quoted();
      if (!av_e) return Expected<XmlNode>::fail(av_e.error());
      const std::string av = av_e.take();
      if (an == "xmlns") {
        scope.default_ns = av;
        node.xmlns.emplace_back("", av);
      } else if (starts_with(an, "xmlns:")) {
        const std::string pfx = an.substr(6);
        scope.prefix_to_uri[pfx] = av;
        node.xmlns.emplace_back(pfx, av);
      } else {
        XmlAttribute attr;
        const auto ac = an.find(':');
        if (ac != std::string::npos) {
          attr.ns = an.substr(0, ac);  // resolved below
          attr.name = an.substr(ac + 1);
          const auto it = scope.prefix_to_uri.find(an.substr(0, ac));
          if (it != scope.prefix_to_uri.end()) attr.ns = it->second;
        } else {
          attr.name = an;
        }
        attr.value = av;
        node.attributes.push_back(std::move(attr));
      }
      skip_ws();
    }

    if (!node.prefix.empty()) {
      const auto it = scope.prefix_to_uri.find(node.prefix);
      if (it != scope.prefix_to_uri.end()) node.ns = it->second;
    } else {
      node.ns = scope.default_ns;
    }

    if (consume("/>")) {
      return Expected<XmlNode>::ok(std::move(node));
    }
    if (!consume(">")) {
      return Expected<XmlNode>::fail(ExitCode::Validation, "expected '>'");
    }

    std::string text_acc;
    while (!eof()) {
      if (starts_with(text.substr(pos), "</")) break;
      if (starts_with(text.substr(pos), "<!--") || starts_with(text.substr(pos), "<?")) {
        skip_comment_or_pi_or_doctype();
        continue;
      }
      if (starts_with(text.substr(pos), "<![CDATA[")) {
        pos += 9;
        const auto end = text.find("]]>", pos);
        const auto raw = text.substr(pos, end == std::string_view::npos ? text.size() - pos
                                                                       : end - pos);
        text_acc.append(raw);
        pos = end == std::string_view::npos ? text.size() : end + 3;
        continue;
      }
      if (peek() == '<') {
        auto child = parse_element(scope);
        if (!child) return Expected<XmlNode>::fail(child.error());
        node.children.push_back(child.take());
      } else {
        const std::size_t start = pos;
        while (!eof() && peek() != '<') ++pos;
        text_acc.append(unescape(text.substr(start, pos - start)));
      }
    }

    // Keep text only if there is non-whitespace content and no element children,
    // or mixed content (preserve trimmed? keep raw trimmed of outer ws).
    auto trimmed = ltrim(text_acc);
    while (!trimmed.empty() &&
           std::isspace(static_cast<unsigned char>(trimmed.back()))) {
      trimmed.remove_suffix(1);
    }
    if (!trimmed.empty()) node.text = std::string(trimmed);

    if (!consume("</")) {
      return Expected<XmlNode>::fail(ExitCode::Validation,
                                     "expected closing tag for " + qname);
    }
    auto close_e = parse_name();
    if (!close_e) return Expected<XmlNode>::fail(close_e.error());
    const std::string close = close_e.take();
    if (close != qname) {
      return Expected<XmlNode>::fail(ExitCode::Validation,
                                     "mismatched close tag: " + close + " vs " + qname);
    }
    skip_ws();
    if (!consume(">")) {
      return Expected<XmlNode>::fail(ExitCode::Validation, "expected '>' after close tag");
    }
    return Expected<XmlNode>::ok(std::move(node));
  }
};

void write_indent(std::ostringstream& os, int n) {
  for (int i = 0; i < n; ++i) os << "  ";
}

std::string qname_of(const XmlNode& node) {
  if (!node.prefix.empty()) return node.prefix + ":" + node.name;
  return node.name;
}

std::string attr_qname(const XmlAttribute& a, const XmlNode& owner) {
  if (a.ns.empty()) return a.name;
  // Prefer a prefix already declared on the owner.
  for (const auto& [pfx, uri] : owner.xmlns) {
    if (uri == a.ns && !pfx.empty()) return pfx + ":" + a.name;
  }
  const auto pfx = prefix_for_namespace(a.ns);
  if (!pfx.empty()) return std::string(pfx) + ":" + a.name;
  return a.name;
}

void serialize_node(std::ostringstream& os, const XmlNode& node, int indent, bool pretty) {
  if (pretty) write_indent(os, indent);
  os << '<' << qname_of(node);
  for (const auto& [pfx, uri] : node.xmlns) {
    os << " xmlns";
    if (!pfx.empty()) os << ':' << pfx;
    os << "=\"" << xml_escape_attr(uri) << '"';
  }
  for (const auto& a : node.attributes) {
    os << ' ' << attr_qname(a, node) << "=\"" << xml_escape_attr(a.value) << '"';
  }
  if (node.children.empty() && node.text.empty()) {
    os << "/>";
    if (pretty) os << '\n';
    return;
  }
  os << '>';
  if (!node.children.empty()) {
    if (pretty) os << '\n';
    for (const auto& c : node.children) serialize_node(os, c, indent + 1, pretty);
    if (!node.text.empty()) {
      if (pretty) write_indent(os, indent + 1);
      os << xml_escape(node.text);
      if (pretty) os << '\n';
    }
    if (pretty) write_indent(os, indent);
    os << "</" << qname_of(node) << '>';
    if (pretty) os << '\n';
  } else {
    os << xml_escape(node.text) << "</" << qname_of(node) << '>';
    if (pretty) os << '\n';
  }
}

}  // namespace

const XmlAttribute* XmlNode::find_attr(std::string_view attr_name) const {
  for (const auto& a : attributes) {
    if (a.name == attr_name) return &a;
  }
  return nullptr;
}

XmlAttribute* XmlNode::find_attr(std::string_view attr_name) {
  for (auto& a : attributes) {
    if (a.name == attr_name) return &a;
  }
  return nullptr;
}

std::string XmlNode::attr(std::string_view attr_name, std::string_view fallback) const {
  if (const auto* a = find_attr(attr_name)) return a->value;
  return std::string(fallback);
}

void XmlNode::set_attr(std::string attr_name, std::string value, std::string attr_ns) {
  if (auto* a = find_attr(attr_name)) {
    a->value = std::move(value);
    if (!attr_ns.empty()) a->ns = std::move(attr_ns);
    return;
  }
  attributes.push_back(XmlAttribute{std::move(attr_name), std::move(value), std::move(attr_ns)});
}

XmlNode* XmlNode::find_child(std::string_view child_name) {
  for (auto& c : children) {
    if (c.name == child_name) return &c;
  }
  return nullptr;
}

const XmlNode* XmlNode::find_child(std::string_view child_name) const {
  for (const auto& c : children) {
    if (c.name == child_name) return &c;
  }
  return nullptr;
}

std::vector<XmlNode*> XmlNode::find_children(std::string_view child_name) {
  std::vector<XmlNode*> out;
  for (auto& c : children) {
    if (c.name == child_name) out.push_back(&c);
  }
  return out;
}

std::vector<const XmlNode*> XmlNode::find_children(std::string_view child_name) const {
  std::vector<const XmlNode*> out;
  for (const auto& c : children) {
    if (c.name == child_name) out.push_back(&c);
  }
  return out;
}

std::string xml_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}

std::string xml_escape_attr(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&apos;";
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}

Expected<XmlDocument> parse_xml(std::string_view text) {
  Parser p{text, 0};
  XmlDocument doc;
  p.skip_ws();
  if (p.consume("<?xml")) {
    while (!p.eof() && !p.consume("?>")) {
      p.skip_ws();
      if (p.consume("version")) {
        p.skip_ws();
        if (!p.consume("=")) {
          return Expected<XmlDocument>::fail(ExitCode::Validation, "bad xml decl");
        }
        p.skip_ws();
        auto v = p.parse_quoted();
        if (!v) return Expected<XmlDocument>::fail(v.error());
        doc.version = v.take();
      } else if (p.consume("encoding")) {
        p.skip_ws();
        if (!p.consume("=")) {
          return Expected<XmlDocument>::fail(ExitCode::Validation, "bad xml decl");
        }
        p.skip_ws();
        auto v = p.parse_quoted();
        if (!v) return Expected<XmlDocument>::fail(v.error());
        doc.encoding = v.take();
      } else {
        p.get();
      }
    }
  }
  p.skip_ws();
  while (!p.eof() && p.peek() == '<' &&
         (starts_with(p.text.substr(p.pos), "<!--") ||
          starts_with(p.text.substr(p.pos), "<?") ||
          starts_with(p.text.substr(p.pos), "<!"))) {
    p.skip_comment_or_pi_or_doctype();
    p.skip_ws();
  }
  auto root = p.parse_element(NsScope{});
  if (!root) return Expected<XmlDocument>::fail(root.error());
  doc.root = root.take();
  return Expected<XmlDocument>::ok(std::move(doc));
}

std::string serialize_xml(const XmlDocument& doc, bool pretty) {
  std::ostringstream os;
  os << "<?xml version=\"" << xml_escape_attr(doc.version) << "\" encoding=\""
     << xml_escape_attr(doc.encoding) << "\"?>";
  if (pretty) os << '\n';
  serialize_node(os, doc.root, 0, pretty);
  return os.str();
}

std::string_view prefix_for_namespace(std::string_view uri) {
  if (uri == kNsUap) return "uap";
  if (uri == kNsUap10) return "uap10";
  if (uri == kNsRescap) return "rescap";
  if (uri == kNsDesktop) return "desktop";
  if (uri == kNsCom) return "com";
  if (uri == kNsMsixAsm) return "msix";
  if (uri == kNsAsmV3) return "asmv3";
  if (uri == kNsCompatV1) return "compatibility";
  if (uri == "http://schemas.microsoft.com/appx/manifest/uap/windows10/2") return "uap2";
  if (uri == "http://schemas.microsoft.com/appx/manifest/uap/windows10/3") return "uap3";
  if (uri == "http://schemas.microsoft.com/appx/manifest/uap/windows10/4") return "uap4";
  if (uri == "http://schemas.microsoft.com/appx/manifest/uap/windows10/5") return "uap5";
  if (uri == "http://schemas.microsoft.com/appx/manifest/desktop/windows10/2") {
    return "desktop2";
  }
  if (uri == "http://schemas.microsoft.com/appx/manifest/desktop/windows10/6") {
    return "desktop6";
  }
  return {};
}

std::string local_name(std::string_view qname) {
  const auto p = qname.rfind(':');
  if (p == std::string_view::npos) return std::string(qname);
  return std::string(qname.substr(p + 1));
}

}  // namespace repackager
