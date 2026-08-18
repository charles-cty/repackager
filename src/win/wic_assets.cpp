#include "repackager/assets.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincodec.h>
#include <wrl/client.h>
#include <shellapi.h>

#include <fstream>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace repackager {
namespace {

bool save_hicon_png(HICON icon, const std::filesystem::path& path, UINT size) {
  if (!icon) return false;
  ComPtr<IWICImagingFactory> factory;
  if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&factory)))) {
    return false;
  }
  ComPtr<IWICBitmap> bitmap;
  if (FAILED(factory->CreateBitmapFromHICON(icon, &bitmap))) return false;
  ComPtr<IWICStream> stream;
  if (FAILED(factory->CreateStream(&stream))) return false;
  if (FAILED(stream->InitializeFromFilename(path.wstring().c_str(), GENERIC_WRITE))) return false;
  ComPtr<IWICBitmapEncoder> encoder;
  if (FAILED(factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder))) return false;
  if (FAILED(encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache))) return false;
  ComPtr<IWICBitmapFrameEncode> frame;
  ComPtr<IPropertyBag2> props;
  if (FAILED(encoder->CreateNewFrame(&frame, &props))) return false;
  if (FAILED(frame->Initialize(props.Get()))) return false;
  if (FAILED(frame->SetSize(size, size))) return false;
  WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGRA;
  if (FAILED(frame->SetPixelFormat(&fmt))) return false;
  if (FAILED(frame->WriteSource(bitmap.Get(), nullptr))) return false;
  if (FAILED(frame->Commit())) return false;
  if (FAILED(encoder->Commit())) return false;
  (void)size;
  return true;
}

}  // namespace

bool try_extract_exe_icon_wic(const std::filesystem::path& exe,
                              const std::filesystem::path& output_dir, AssetSet& set) {
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  HICON large_icon = nullptr;
  HICON small_icon = nullptr;
  const UINT n = ExtractIconExW(exe.wstring().c_str(), 0, &large_icon, &small_icon, 1);
  if (n == 0) {
    CoUninitialize();
    return false;
  }
  bool any = false;
  if (large_icon) {
    any |= save_hicon_png(large_icon, output_dir / "Square150x150Logo.png", 150);
    any |= save_hicon_png(large_icon, output_dir / "StoreLogo.png", 50);
    DestroyIcon(large_icon);
  }
  if (small_icon) {
    any |= save_hicon_png(small_icon, output_dir / "Square44x44Logo.png", 44);
    DestroyIcon(small_icon);
  }
  CoUninitialize();
  if (any) {
    set.store_logo = output_dir / "StoreLogo.png";
    set.square44 = output_dir / "Square44x44Logo.png";
    set.square150 = output_dir / "Square150x150Logo.png";
  }
  return any;
}

}  // namespace repackager
#endif
