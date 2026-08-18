#include "repackager/xml.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <msxml6.h>
#include <wrl/client.h>

#include <string>

using Microsoft::WRL::ComPtr;

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

class ComInit {
 public:
  ComInit() { CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); }
  ~ComInit() { CoUninitialize(); }
};

}  // namespace

Expected<XmlDocument> parse_xml_msxml6(std::string_view text) {
  ComInit com;
  ComPtr<IXMLDOMDocument3> doc;
  const HRESULT hr = CoCreateInstance(__uuidof(DOMDocument60), nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(&doc));
  if (FAILED(hr) || !doc) {
    return Expected<XmlDocument>::fail(ExitCode::Environment, "MSXML6 is unavailable");
  }
  doc->put_async(VARIANT_FALSE);
  doc->put_validateOnParse(VARIANT_FALSE);
  doc->put_resolveExternals(VARIANT_FALSE);
  VARIANT_BOOL ok = VARIANT_FALSE;
  const auto w = widen(text);
  BSTR xml = SysAllocStringLen(w.data(), static_cast<UINT>(w.size()));
  const HRESULT lhr = doc->loadXML(xml, &ok);
  SysFreeString(xml);
  if (FAILED(lhr) || ok != VARIANT_TRUE) {
    return Expected<XmlDocument>::fail(ExitCode::Validation, "MSXML6 rejected the XML");
  }
  BSTR out = nullptr;
  doc->get_xml(&out);
  std::string utf8;
  if (out) {
    utf8 = narrow(out);
    SysFreeString(out);
  }
  return parse_xml(utf8);
}

Expected<std::string> serialize_xml_msxml6(const XmlDocument& document) {
  ComInit com;
  ComPtr<IXMLDOMDocument3> doc;
  const HRESULT hr = CoCreateInstance(__uuidof(DOMDocument60), nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(&doc));
  if (FAILED(hr) || !doc) {
    return Expected<std::string>::fail(ExitCode::Environment, "MSXML6 is unavailable");
  }
  doc->put_async(VARIANT_FALSE);
  const auto text = serialize_xml(document, true);
  const auto w = widen(text);
  BSTR xml = SysAllocStringLen(w.data(), static_cast<UINT>(w.size()));
  VARIANT_BOOL ok = VARIANT_FALSE;
  doc->loadXML(xml, &ok);
  SysFreeString(xml);
  if (ok != VARIANT_TRUE) {
    return Expected<std::string>::ok(text);
  }
  BSTR out = nullptr;
  doc->get_xml(&out);
  std::string utf8 = text;
  if (out) {
    utf8 = narrow(out);
    SysFreeString(out);
  }
  return Expected<std::string>::ok(std::move(utf8));
}

}  // namespace repackager
#endif
