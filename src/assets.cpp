#include "repackager/assets.hpp"

#include "repackager/hash.hpp"
#include "repackager/journal.hpp"

#include <algorithm>
#include <fstream>

namespace repackager {
namespace {

std::uint32_t crc32_ieee(const std::uint8_t* data, std::size_t len) {
  std::uint32_t crc = 0xffffffffu;
  for (std::size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (int b = 0; b < 8; ++b) {
      const std::uint32_t mask = static_cast<std::uint32_t>(-(static_cast<std::int32_t>(crc & 1)));
      crc = (crc >> 1) ^ (0xedb88320u & mask);
    }
  }
  return ~crc;
}

void be32(std::vector<std::uint8_t>& o, std::uint32_t v) {
  o.push_back(static_cast<std::uint8_t>(v >> 24));
  o.push_back(static_cast<std::uint8_t>(v >> 16));
  o.push_back(static_cast<std::uint8_t>(v >> 8));
  o.push_back(static_cast<std::uint8_t>(v));
}

void chunk(std::vector<std::uint8_t>& o, const char* type, const std::vector<std::uint8_t>& data) {
  be32(o, static_cast<std::uint32_t>(data.size()));
  const std::size_t type_off = o.size();
  o.insert(o.end(), type, type + 4);
  o.insert(o.end(), data.begin(), data.end());
  const auto crc = crc32_ieee(o.data() + type_off, 4 + data.size());
  be32(o, crc);
}

// zlib-wrapped uncompressed deflate blocks (BTYPE=00).
std::vector<std::uint8_t> zlib_store(const std::vector<std::uint8_t>& raw) {
  std::vector<std::uint8_t> out;
  out.push_back(0x78);
  out.push_back(0x01);
  std::size_t i = 0;
  while (i < raw.size()) {
    const std::size_t n = std::min<std::size_t>(65535, raw.size() - i);
    const bool last = i + n >= raw.size();
    out.push_back(last ? 0x01 : 0x00);
    out.push_back(static_cast<std::uint8_t>(n & 0xff));
    out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xff));
    const std::uint16_t ninv = static_cast<std::uint16_t>(~n);
    out.push_back(static_cast<std::uint8_t>(ninv & 0xff));
    out.push_back(static_cast<std::uint8_t>((ninv >> 8) & 0xff));
    out.insert(out.end(), raw.begin() + static_cast<std::ptrdiff_t>(i),
               raw.begin() + static_cast<std::ptrdiff_t>(i + n));
    i += n;
  }
  std::uint32_t s1 = 1, s2 = 0;
  for (auto b : raw) {
    s1 = (s1 + b) % 65521;
    s2 = (s2 + s1) % 65521;
  }
  const std::uint32_t adler = (s2 << 16) | s1;
  be32(out, adler);
  return out;
}

}  // namespace

std::vector<std::uint8_t> make_placeholder_png(int width, int height, std::string_view seed) {
  const auto digest = sha256_string(seed);
  const std::uint8_t r = digest[0];
  const std::uint8_t g = digest[1];
  const std::uint8_t b = digest[2];
  std::vector<std::uint8_t> raw;
  raw.reserve(static_cast<std::size_t>(height) * (static_cast<std::size_t>(width) * 3 + 1));
  for (int y = 0; y < height; ++y) {
    raw.push_back(0);
    for (int x = 0; x < width; ++x) {
      const bool band = ((x / 4) + (y / 4)) % 2 == 0;
      raw.push_back(band ? r : static_cast<std::uint8_t>(255 - r));
      raw.push_back(band ? g : static_cast<std::uint8_t>(255 - g));
      raw.push_back(band ? b : static_cast<std::uint8_t>(255 - b));
    }
  }
  std::vector<std::uint8_t> png = {137, 80, 78, 71, 13, 10, 26, 10};
  std::vector<std::uint8_t> ihdr;
  be32(ihdr, static_cast<std::uint32_t>(width));
  be32(ihdr, static_cast<std::uint32_t>(height));
  ihdr.push_back(8);
  ihdr.push_back(2);
  ihdr.push_back(0);
  ihdr.push_back(0);
  ihdr.push_back(0);
  chunk(png, "IHDR", ihdr);
  chunk(png, "IDAT", zlib_store(raw));
  chunk(png, "IEND", {});
  return png;
}

Expected<AssetSet> generate_assets(const std::filesystem::path& output_dir,
                                   const std::filesystem::path& exe, std::string_view seed,
                                   OperationJournal* journal) {
  AssetSet set;
  std::error_code ec;
  std::filesystem::create_directories(output_dir, ec);
  set.store_logo = output_dir / "StoreLogo.png";
  set.square44 = output_dir / "Square44x44Logo.png";
  set.square150 = output_dir / "Square150x150Logo.png";

#ifdef _WIN32
  if (!exe.empty() && std::filesystem::exists(exe)) {
    if (try_extract_exe_icon_wic(exe, output_dir, set)) {
      set.from_exe_icon = true;
    }
  }
#else
  (void)exe;
#endif

  auto write_png = [&](const std::filesystem::path& path, int w, int h) {
    if (std::filesystem::exists(path)) return Status::success();
    const auto bytes = make_placeholder_png(w, h, seed);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return Status::fail(ExitCode::Internal, "cannot write " + path.string());
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    CreatedPath cp{path.string(), sha256_file_hex(path)};
    set.created.push_back(cp);
    if (journal) journal_record_path(*journal, path);
    return Status::success();
  };

  if (auto s = write_png(set.store_logo, 50, 50); !s) {
    return Expected<AssetSet>::fail(s.code, s.message);
  }
  if (auto s = write_png(set.square44, 44, 44); !s) {
    return Expected<AssetSet>::fail(s.code, s.message);
  }
  if (auto s = write_png(set.square150, 150, 150); !s) {
    return Expected<AssetSet>::fail(s.code, s.message);
  }
  return Expected<AssetSet>::ok(std::move(set));
}

}  // namespace repackager
