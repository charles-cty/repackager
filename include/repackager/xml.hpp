#pragma once

#include "repackager/error.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace repackager {

struct XmlAttribute {
  std::string name;
  std::string value;
  std::string ns;
};

struct XmlNode {
  std::string name;
  std::string ns;
  std::string prefix;
  std::string text;
  std::vector<XmlAttribute> attributes;
  std::vector<XmlNode> children;
  std::vector<std::pair<std::string, std::string>> xmlns;  // prefix, uri

  const XmlAttribute* find_attr(std::string_view name) const;
  XmlAttribute* find_attr(std::string_view name);
  std::string attr(std::string_view name, std::string_view fallback = {}) const;
  void set_attr(std::string name, std::string value, std::string ns = {});
  XmlNode* find_child(std::string_view name);
  const XmlNode* find_child(std::string_view name) const;
  std::vector<XmlNode*> find_children(std::string_view name);
  std::vector<const XmlNode*> find_children(std::string_view name) const;
};

struct XmlDocument {
  XmlNode root;
  std::string version{"1.0"};
  std::string encoding{"utf-8"};
};

std::string xml_escape(std::string_view text);
std::string xml_escape_attr(std::string_view text);

Expected<XmlDocument> parse_xml(std::string_view text);
std::string serialize_xml(const XmlDocument& doc, bool pretty = true);

// Well-known Appx / MSIX namespaces.
inline constexpr std::string_view kNsFoundation =
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
inline constexpr std::string_view kNsUap =
    "http://schemas.microsoft.com/appx/manifest/uap/windows10";
inline constexpr std::string_view kNsUap10 =
    "http://schemas.microsoft.com/appx/manifest/uap/windows10/10";
inline constexpr std::string_view kNsRescap =
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities";
inline constexpr std::string_view kNsDesktop =
    "http://schemas.microsoft.com/appx/manifest/desktop/windows10";
inline constexpr std::string_view kNsCom =
    "http://schemas.microsoft.com/appx/manifest/com/windows10";
inline constexpr std::string_view kNsMsixAsm = "urn:schemas-microsoft-com:msix.v1";
inline constexpr std::string_view kNsAsmV1 = "urn:schemas-microsoft-com:asm.v1";
inline constexpr std::string_view kNsAsmV3 = "urn:schemas-microsoft-com:asm.v3";
inline constexpr std::string_view kNsCompatV1 =
    "urn:schemas-microsoft-com:compatibility.v1";
inline constexpr std::string_view kNsWindowsSettings =
    "http://schemas.microsoft.com/SMI/2005/WindowsSettings";
inline constexpr std::string_view kNsWindowsSettings2016 =
    "http://schemas.microsoft.com/SMI/2016/WindowsSettings";

std::string_view prefix_for_namespace(std::string_view uri);
std::string local_name(std::string_view qname);

#ifdef _WIN32
Expected<XmlDocument> parse_xml_msxml6(std::string_view text);
Expected<std::string> serialize_xml_msxml6(const XmlDocument& doc);
#endif

}  // namespace repackager
