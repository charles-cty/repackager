#include "repackager/zip.hpp"

#include <cstring>
#include <fstream>

namespace repackager {
namespace {

#pragma pack(push, 1)
struct LocalHeader {
  std::uint32_t sig;
  std::uint16_t version;
  std::uint16_t flags;
  std::uint16_t method;
  std::uint16_t mod_time;
  std::uint16_t mod_date;
  std::uint32_t crc;
  std::uint32_t compressed;
  std::uint32_t uncompressed;
  std::uint16_t name_len;
  std::uint16_t extra_len;
};
struct CentralHeader {
  std::uint32_t sig;
  std::uint16_t made_by;
  std::uint16_t version;
  std::uint16_t flags;
  std::uint16_t method;
  std::uint16_t mod_time;
  std::uint16_t mod_date;
  std::uint32_t crc;
  std::uint32_t compressed;
  std::uint32_t uncompressed;
  std::uint16_t name_len;
  std::uint16_t extra_len;
  std::uint16_t comment_len;
  std::uint16_t disk;
  std::uint16_t int_attr;
  std::uint32_t ext_attr;
  std::uint32_t local_off;
};
struct EndRecord {
  std::uint32_t sig;
  std::uint16_t disk;
  std::uint16_t start_disk;
  std::uint16_t entries_this_disk;
  std::uint16_t entries;
  std::uint32_t central_size;
  std::uint32_t central_off;
  std::uint16_t comment_len;
};
#pragma pack(pop)

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

bool read_all(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  return true;
}

}  // namespace

Expected<std::vector<ZipEntry>> zip_read(const std::filesystem::path& path) {
  std::vector<std::uint8_t> bytes;
  if (!read_all(path, bytes)) {
    return Expected<std::vector<ZipEntry>>::fail(ExitCode::NotFound,
                                                 "cannot read zip: " + path.string());
  }
  if (bytes.size() < sizeof(EndRecord)) {
    return Expected<std::vector<ZipEntry>>::fail(ExitCode::Validation, "file too small to be zip");
  }
  std::int64_t eocd = -1;
  for (std::int64_t i = static_cast<std::int64_t>(bytes.size()) - 22; i >= 0; --i) {
    if (bytes[static_cast<std::size_t>(i)] == 0x50 &&
        bytes[static_cast<std::size_t>(i) + 1] == 0x4b &&
        bytes[static_cast<std::size_t>(i) + 2] == 0x05 &&
        bytes[static_cast<std::size_t>(i) + 3] == 0x06) {
      eocd = i;
      break;
    }
    if (static_cast<std::size_t>(bytes.size()) - static_cast<std::size_t>(i) > 65557) break;
  }
  if (eocd < 0) {
    return Expected<std::vector<ZipEntry>>::fail(ExitCode::Validation, "zip EOCD not found");
  }
  EndRecord end{};
  std::memcpy(&end, bytes.data() + eocd, sizeof(end));
  std::vector<ZipEntry> entries;
  std::uint32_t off = end.central_off;
  for (std::uint16_t n = 0; n < end.entries; ++n) {
    if (off + sizeof(CentralHeader) > bytes.size()) break;
    CentralHeader ch{};
    std::memcpy(&ch, bytes.data() + off, sizeof(ch));
    if (ch.sig != 0x02014b50) {
      return Expected<std::vector<ZipEntry>>::fail(ExitCode::Validation, "bad central header");
    }
    ZipEntry e;
    e.name.assign(reinterpret_cast<const char*>(bytes.data() + off + sizeof(ch)), ch.name_len);
    e.is_directory = !e.name.empty() && e.name.back() == '/';
    const std::uint32_t local = ch.local_off;
    if (local + sizeof(LocalHeader) > bytes.size()) {
      return Expected<std::vector<ZipEntry>>::fail(ExitCode::Validation, "bad local header offset");
    }
    LocalHeader lh{};
    std::memcpy(&lh, bytes.data() + local, sizeof(lh));
    const std::uint32_t data_off = local + sizeof(LocalHeader) + lh.name_len + lh.extra_len;
    if (lh.method != 0) {
      return Expected<std::vector<ZipEntry>>::fail(
          ExitCode::Environment, "zip entry uses compression (only STORE is supported here): " + e.name);
    }
    if (data_off + lh.uncompressed > bytes.size()) {
      return Expected<std::vector<ZipEntry>>::fail(ExitCode::Validation, "truncated zip data");
    }
    e.data.assign(bytes.begin() + data_off, bytes.begin() + data_off + lh.uncompressed);
    entries.push_back(std::move(e));
    off += sizeof(CentralHeader) + ch.name_len + ch.extra_len + ch.comment_len;
  }
  return Expected<std::vector<ZipEntry>>::ok(std::move(entries));
}

Status zip_write(const std::filesystem::path& path, const std::vector<ZipEntry>& entries) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return Status::fail(ExitCode::Internal, "cannot write zip: " + path.string());
  struct Meta {
    std::uint32_t local_off;
    std::uint32_t crc;
    std::uint32_t size;
    std::string name;
  };
  std::vector<Meta> meta;
  for (const auto& e : entries) {
    Meta m;
    m.local_off = static_cast<std::uint32_t>(out.tellp());
    m.crc = crc32_ieee(e.data.data(), e.data.size());
    m.size = static_cast<std::uint32_t>(e.data.size());
    m.name = e.name;
    LocalHeader lh{};
    lh.sig = 0x04034b50;
    lh.version = 20;
    lh.method = 0;
    lh.crc = m.crc;
    lh.compressed = m.size;
    lh.uncompressed = m.size;
    lh.name_len = static_cast<std::uint16_t>(m.name.size());
    out.write(reinterpret_cast<const char*>(&lh), sizeof(lh));
    out.write(m.name.data(), static_cast<std::streamsize>(m.name.size()));
    if (!e.data.empty()) {
      out.write(reinterpret_cast<const char*>(e.data.data()),
                static_cast<std::streamsize>(e.data.size()));
    }
    meta.push_back(std::move(m));
  }
  const auto central_off = static_cast<std::uint32_t>(out.tellp());
  for (const auto& m : meta) {
    CentralHeader ch{};
    ch.sig = 0x02014b50;
    ch.made_by = 20;
    ch.version = 20;
    ch.method = 0;
    ch.crc = m.crc;
    ch.compressed = m.size;
    ch.uncompressed = m.size;
    ch.name_len = static_cast<std::uint16_t>(m.name.size());
    ch.local_off = m.local_off;
    out.write(reinterpret_cast<const char*>(&ch), sizeof(ch));
    out.write(m.name.data(), static_cast<std::streamsize>(m.name.size()));
  }
  const auto central_end = static_cast<std::uint32_t>(out.tellp());
  EndRecord end{};
  end.sig = 0x06054b50;
  end.entries_this_disk = static_cast<std::uint16_t>(meta.size());
  end.entries = static_cast<std::uint16_t>(meta.size());
  end.central_size = central_end - central_off;
  end.central_off = central_off;
  out.write(reinterpret_cast<const char*>(&end), sizeof(end));
  return Status::success();
}

}  // namespace repackager
