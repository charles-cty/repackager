#include "repackager/pe.hpp"

#include "repackager/hash.hpp"
#include "repackager/toolchain.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace repackager {
namespace {

constexpr std::uint16_t kDosMagic = 0x5A4D;
constexpr std::uint32_t kPeMagic = 0x00004550;
constexpr std::uint16_t kPe32 = 0x10b;
constexpr std::uint16_t kPe32Plus = 0x20b;
constexpr int kDirResource = 2;
constexpr int kDirSecurity = 4;
constexpr std::uint16_t kRtManifest = 24;
constexpr std::uint16_t kRtVersion = 16;

#pragma pack(push, 1)
struct DosHeader {
  std::uint16_t e_magic;
  std::uint16_t pad[29];
  std::uint32_t e_lfanew;
};
struct CoffHeader {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};
struct DataDir {
  std::uint32_t va;
  std::uint32_t size;
};
struct SectionHeader {
  char name[8];
  std::uint32_t virtual_size;
  std::uint32_t virtual_address;
  std::uint32_t size_of_raw_data;
  std::uint32_t pointer_to_raw_data;
  std::uint32_t pointer_to_relocations;
  std::uint32_t pointer_to_linenumbers;
  std::uint16_t number_of_relocations;
  std::uint16_t number_of_linenumbers;
  std::uint32_t characteristics;
};
struct ResDir {
  std::uint32_t characteristics;
  std::uint32_t time_date_stamp;
  std::uint16_t major;
  std::uint16_t minor;
  std::uint16_t named;
  std::uint16_t id_entries;
};
struct ResEntry {
  std::uint32_t name;
  std::uint32_t offset;
};
struct ResData {
  std::uint32_t offset_to_data;
  std::uint32_t size;
  std::uint32_t code_page;
  std::uint32_t reserved;
};
#pragma pack(pop)

bool read_file(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  return true;
}

bool write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return false;
  out.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(out);
}

template <typename T>
bool read_at(const std::vector<std::uint8_t>& b, std::size_t off, T& out) {
  if (off + sizeof(T) > b.size()) return false;
  std::memcpy(&out, b.data() + off, sizeof(T));
  return true;
}

std::uint32_t align_up(std::uint32_t v, std::uint32_t a) {
  if (!a) return v;
  return (v + a - 1) & ~(a - 1);
}

struct PeView {
  std::vector<std::uint8_t> bytes;
  std::uint32_t lfanew = 0;
  CoffHeader coff{};
  std::uint16_t opt_magic = 0;
  std::uint32_t opt_off = 0;
  std::uint32_t data_dir_off = 0;
  std::uint32_t number_of_rva_and_sizes = 0;
  std::uint32_t section_align = 0x1000;
  std::uint32_t file_align = 0x200;
  std::uint32_t size_of_image_off = 0;
  std::uint32_t size_of_headers_off = 0;
  std::uint32_t sections_off = 0;
  Architecture arch = Architecture::Neutral;
  bool is_dll = false;
};

Expected<PeView> parse_pe(const std::filesystem::path& path) {
  PeView v;
  if (!read_file(path, v.bytes)) {
    return Expected<PeView>::fail(ExitCode::NotFound, "cannot read PE: " + path.string());
  }
  DosHeader dos{};
  if (!read_at(v.bytes, 0, dos) || dos.e_magic != kDosMagic) {
    return Expected<PeView>::fail(ExitCode::Validation, "not a PE file");
  }
  v.lfanew = dos.e_lfanew;
  std::uint32_t sig = 0;
  if (!read_at(v.bytes, v.lfanew, sig) || sig != kPeMagic) {
    return Expected<PeView>::fail(ExitCode::Validation, "missing PE signature");
  }
  if (!read_at(v.bytes, v.lfanew + 4, v.coff)) {
    return Expected<PeView>::fail(ExitCode::Validation, "truncated COFF header");
  }
  v.opt_off = v.lfanew + 4 + sizeof(CoffHeader);
  if (!read_at(v.bytes, v.opt_off, v.opt_magic)) {
    return Expected<PeView>::fail(ExitCode::Validation, "truncated optional header");
  }
  switch (v.coff.machine) {
    case 0x014c:
      v.arch = Architecture::X86;
      break;
    case 0x8664:
      v.arch = Architecture::X64;
      break;
    case 0x01c0:
    case 0x01c4:
      v.arch = Architecture::Arm;
      break;
    case 0xaa64:
      v.arch = Architecture::Arm64;
      break;
    default:
      v.arch = Architecture::Neutral;
      break;
  }
  v.is_dll = (v.coff.characteristics & 0x2000) != 0;
  if (v.opt_magic == kPe32) {
    v.section_align = 0;
    v.file_align = 0;
    read_at(v.bytes, v.opt_off + 32, v.section_align);
    read_at(v.bytes, v.opt_off + 36, v.file_align);
    v.size_of_image_off = v.opt_off + 56;
    v.size_of_headers_off = v.opt_off + 60;
    std::uint32_t rvas = 0;
    read_at(v.bytes, v.opt_off + 92, rvas);
    v.number_of_rva_and_sizes = rvas;
    v.data_dir_off = v.opt_off + 96;
  } else if (v.opt_magic == kPe32Plus) {
    read_at(v.bytes, v.opt_off + 36, v.section_align);
    read_at(v.bytes, v.opt_off + 40, v.file_align);
    v.size_of_image_off = v.opt_off + 56;
    v.size_of_headers_off = v.opt_off + 60;
    std::uint32_t rvas = 0;
    read_at(v.bytes, v.opt_off + 108, rvas);
    v.number_of_rva_and_sizes = rvas;
    v.data_dir_off = v.opt_off + 112;
  } else {
    return Expected<PeView>::fail(ExitCode::Validation, "unknown optional header magic");
  }
  if (!v.section_align) v.section_align = 0x1000;
  if (!v.file_align) v.file_align = 0x200;
  v.sections_off = v.opt_off + v.coff.size_of_optional_header;
  return Expected<PeView>::ok(std::move(v));
}

DataDir data_dir(const PeView& v, int index) {
  DataDir d{};
  if (static_cast<std::uint32_t>(index) >= v.number_of_rva_and_sizes) return d;
  read_at(v.bytes, v.data_dir_off + static_cast<std::size_t>(index) * sizeof(DataDir), d);
  return d;
}

void set_data_dir(PeView& v, int index, DataDir d) {
  if (static_cast<std::uint32_t>(index) >= v.number_of_rva_and_sizes) return;
  std::memcpy(v.bytes.data() + v.data_dir_off + static_cast<std::size_t>(index) * sizeof(DataDir),
              &d, sizeof(d));
}

void strip_authenticode(PeView& v) {
  const auto security = data_dir(v, kDirSecurity);
  set_data_dir(v, kDirSecurity, {});

  // The security directory uses a file offset rather than an RVA. Remove a
  // trailing certificate table, but preserve any overlay that follows it.
  const auto certificate_offset = static_cast<std::size_t>(security.va);
  const auto certificate_size = static_cast<std::size_t>(security.size);
  if (certificate_offset <= v.bytes.size() &&
      certificate_size <= v.bytes.size() - certificate_offset &&
      certificate_offset + certificate_size == v.bytes.size()) {
    v.bytes.resize(certificate_offset);
  }
}

std::vector<SectionHeader> sections(const PeView& v) {
  std::vector<SectionHeader> out;
  out.resize(v.coff.number_of_sections);
  for (std::uint16_t i = 0; i < v.coff.number_of_sections; ++i) {
    read_at(v.bytes, v.sections_off + i * sizeof(SectionHeader), out[i]);
  }
  return out;
}

std::uint32_t rva_to_off(const PeView& v, std::uint32_t rva) {
  for (const auto& s : sections(v)) {
    const auto start = s.virtual_address;
    const auto span = std::max(s.virtual_size, s.size_of_raw_data);
    if (rva >= start && rva < start + span) {
      return s.pointer_to_raw_data + (rva - start);
    }
  }
  return 0;
}

struct ResLeaf {
  std::uint32_t type = 0;
  std::uint32_t id = 0;
  std::uint32_t lang = 0;
  std::vector<std::uint8_t> data;
};

void walk_res(const PeView& v, std::uint32_t root_rva, std::uint32_t dir_rva, int level,
              std::uint32_t type, std::uint32_t id, std::vector<ResLeaf>& out) {
  const auto off = rva_to_off(v, dir_rva);
  ResDir dir{};
  if (!read_at(v.bytes, off, dir)) return;
  const int count = dir.named + dir.id_entries;
  for (int i = 0; i < count; ++i) {
    ResEntry e{};
    if (!read_at(v.bytes, off + sizeof(ResDir) + i * sizeof(ResEntry), e)) continue;
    const std::uint32_t name_or_id = e.name;
    const bool is_dir = (e.offset & 0x80000000u) != 0;
    const std::uint32_t next = root_rva + (e.offset & 0x7fffffffu);
    std::uint32_t t = type, n = id, lang = 0;
    const std::uint32_t key = name_or_id & 0x7fffffffu;
    if (level == 0) t = key;
    else if (level == 1) n = key;
    else lang = key;
    if (is_dir) {
      walk_res(v, root_rva, next, level + 1, t, n, out);
    } else {
      const auto doff = rva_to_off(v, next);
      ResData rd{};
      if (!read_at(v.bytes, doff, rd)) continue;
      const auto raw = rva_to_off(v, rd.offset_to_data);
      if (raw + rd.size > v.bytes.size()) continue;
      ResLeaf leaf;
      leaf.type = t;
      leaf.id = n;
      leaf.lang = lang;
      leaf.data.assign(v.bytes.begin() + raw, v.bytes.begin() + raw + rd.size);
      out.push_back(std::move(leaf));
    }
  }
}

std::string utf16le_to_utf8(const std::uint16_t* p, std::size_t n) {
  std::string out;
  for (std::size_t i = 0; i < n && p[i]; ++i) {
    const std::uint16_t c = p[i];
    if (c < 0x80) out.push_back(static_cast<char>(c));
    else if (c < 0x800) {
      out.push_back(static_cast<char>(0xc0 | (c >> 6)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3f)));
    } else {
      out.push_back(static_cast<char>(0xe0 | (c >> 12)));
      out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3f)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3f)));
    }
  }
  return out;
}

void parse_version_info(const std::vector<std::uint8_t>& data, PeInspection& info) {
  if (data.size() < 52) return;
  // VS_FIXEDFILEINFO typically starts after wLength/wValueLength/wType + "VS_VERSION_INFO\0" pad
  std::size_t i = 6;
  // skip key
  while (i + 1 < data.size()) {
    std::uint16_t ch = 0;
    std::memcpy(&ch, data.data() + i, 2);
    i += 2;
    if (ch == 0) break;
  }
  i = (i + 3) & ~std::size_t{3};
  if (i + 52 > data.size()) return;
  std::uint32_t sig = 0;
  std::memcpy(&sig, data.data() + i, 4);
  if (sig != 0xFEEF04BD) return;
  std::uint32_t ms = 0, ls = 0;
  std::memcpy(&ms, data.data() + i + 8, 4);
  std::memcpy(&ls, data.data() + i + 12, 4);
  std::ostringstream ver;
  ver << ((ms >> 16) & 0xffff) << '.' << (ms & 0xffff) << '.' << ((ls >> 16) & 0xffff)
      << '.' << (ls & 0xffff);
  info.file_version = ver.str();

  // Best-effort string table scan for FileDescription / ProductName.
  auto find_str = [&](const char* key) -> std::string {
    const std::u16string needle = std::u16string(key, key + std::strlen(key));
    for (std::size_t p = 0; p + needle.size() * 2 + 4 < data.size(); ++p) {
      bool match = true;
      for (std::size_t k = 0; k < needle.size(); ++k) {
        std::uint16_t ch = 0;
        std::memcpy(&ch, data.data() + p + k * 2, 2);
        if (ch != static_cast<std::uint16_t>(needle[k])) {
          match = false;
          break;
        }
      }
      if (!match) continue;
      std::uint16_t z = 0;
      std::memcpy(&z, data.data() + p + needle.size() * 2, 2);
      if (z != 0) continue;
      std::size_t val = (p + needle.size() * 2 + 2 + 3) & ~std::size_t{3};
      if (val >= data.size()) continue;
      const auto* up = reinterpret_cast<const std::uint16_t*>(data.data() + val);
      const std::size_t maxn = (data.size() - val) / 2;
      return utf16le_to_utf8(up, maxn);
    }
    return {};
  };
  info.file_description = find_str("FileDescription");
  info.product_name = find_str("ProductName");
}

std::uint32_t pad4(std::uint32_t v) { return (v + 3u) & ~3u; }

// Rebuild a simple resource tree from leaves. Layout: directories then data
// entries then blobs. RVAs are relative to the resource section VA.
std::vector<std::uint8_t> build_rsrc(const std::vector<ResLeaf>& leaves,
                                     std::uint32_t section_va) {
  // Group type -> id -> lang
  struct Lang {
    std::uint32_t lang;
    std::vector<std::uint8_t> data;
  };
  struct Id {
    std::uint32_t id;
    std::vector<Lang> langs;
  };
  struct Type {
    std::uint32_t type;
    std::vector<Id> ids;
  };
  std::vector<Type> types;
  for (const auto& leaf : leaves) {
    Type* t = nullptr;
    for (auto& x : types) {
      if (x.type == leaf.type) t = &x;
    }
    if (!t) {
      types.push_back(Type{leaf.type, {}});
      t = &types.back();
    }
    Id* idp = nullptr;
    for (auto& x : t->ids) {
      if (x.id == leaf.id) idp = &x;
    }
    if (!idp) {
      t->ids.push_back(Id{leaf.id, {}});
      idp = &t->ids.back();
    }
    idp->langs.push_back(Lang{leaf.lang, leaf.data});
  }

  // Count directories to assign offsets.
  // Root dir + one dir per type + one dir per id.
  std::uint32_t dir_bytes = sizeof(ResDir) + static_cast<std::uint32_t>(types.size()) * sizeof(ResEntry);
  for (const auto& t : types) {
    dir_bytes += sizeof(ResDir) + static_cast<std::uint32_t>(t.ids.size()) * sizeof(ResEntry);
    for (const auto& id : t.ids) {
      dir_bytes += sizeof(ResDir) + static_cast<std::uint32_t>(id.langs.size()) * sizeof(ResEntry);
    }
  }
  std::uint32_t data_entry_count = 0;
  std::uint32_t blob_size = 0;
  for (const auto& t : types)
    for (const auto& id : t.ids)
      for (const auto& l : id.langs) {
        ++data_entry_count;
        blob_size += pad4(static_cast<std::uint32_t>(l.data.size()));
      }
  const std::uint32_t data_entries_off = dir_bytes;
  const std::uint32_t blobs_off = data_entries_off + data_entry_count * sizeof(ResData);
  std::vector<std::uint8_t> buf(blobs_off + blob_size, 0);

  auto write_dir = [&](std::uint32_t off, std::uint16_t count) {
    ResDir d{};
    d.id_entries = count;
    std::memcpy(buf.data() + off, &d, sizeof(d));
  };

  std::uint32_t cursor = 0;
  std::uint32_t next_dir = sizeof(ResDir) + static_cast<std::uint32_t>(types.size()) * sizeof(ResEntry);
  std::uint32_t next_data = data_entries_off;
  std::uint32_t next_blob = blobs_off;

  write_dir(0, static_cast<std::uint16_t>(types.size()));
  cursor = sizeof(ResDir);
  for (const auto& t : types) {
    ResEntry e{};
    e.name = t.type;
    e.offset = 0x80000000u | next_dir;
    std::memcpy(buf.data() + cursor, &e, sizeof(e));
    cursor += sizeof(ResEntry);

    const std::uint32_t type_dir = next_dir;
    next_dir += sizeof(ResDir) + static_cast<std::uint32_t>(t.ids.size()) * sizeof(ResEntry);
    write_dir(type_dir, static_cast<std::uint16_t>(t.ids.size()));
    std::uint32_t id_cursor = type_dir + sizeof(ResDir);
    for (const auto& id : t.ids) {
      ResEntry ie{};
      ie.name = id.id;
      ie.offset = 0x80000000u | next_dir;
      std::memcpy(buf.data() + id_cursor, &ie, sizeof(ie));
      id_cursor += sizeof(ResEntry);

      const std::uint32_t id_dir = next_dir;
      next_dir += sizeof(ResDir) + static_cast<std::uint32_t>(id.langs.size()) * sizeof(ResEntry);
      write_dir(id_dir, static_cast<std::uint16_t>(id.langs.size()));
      std::uint32_t lang_cursor = id_dir + sizeof(ResDir);
      for (const auto& l : id.langs) {
        ResEntry le{};
        le.name = l.lang;
        le.offset = next_data;
        std::memcpy(buf.data() + lang_cursor, &le, sizeof(le));
        lang_cursor += sizeof(ResEntry);

        ResData rd{};
        rd.offset_to_data = section_va + next_blob;
        rd.size = static_cast<std::uint32_t>(l.data.size());
        rd.code_page = 0;
        std::memcpy(buf.data() + next_data, &rd, sizeof(rd));
        next_data += sizeof(ResData);
        std::memcpy(buf.data() + next_blob, l.data.data(), l.data.size());
        next_blob += pad4(static_cast<std::uint32_t>(l.data.size()));
      }
    }
  }
  return buf;
}

Status embed_manifest_portable(PeView& v, std::string_view manifest_xml) {
  const auto res_dir = data_dir(v, kDirResource);
  std::vector<ResLeaf> leaves;
  if (res_dir.va && res_dir.size) {
    walk_res(v, res_dir.va, res_dir.va, 0, 0, 0, leaves);
  }
  bool replaced = false;
  for (auto& leaf : leaves) {
    if (leaf.type == kRtManifest) {
      leaf.data.assign(manifest_xml.begin(), manifest_xml.end());
      replaced = true;
    }
  }
  if (!replaced) {
    ResLeaf leaf;
    leaf.type = kRtManifest;
    leaf.id = 1;
    leaf.lang = 0x0409;
    leaf.data.assign(manifest_xml.begin(), manifest_xml.end());
    leaves.push_back(std::move(leaf));
  }

  auto secs = sections(v);
  SectionHeader* rsrc = nullptr;
  int rsrc_index = -1;
  for (std::size_t i = 0; i < secs.size(); ++i) {
    if (std::strncmp(secs[i].name, ".rsrc", 5) == 0) {
      rsrc = &secs[i];
      rsrc_index = static_cast<int>(i);
    }
  }

  std::uint32_t section_va = rsrc ? rsrc->virtual_address : 0;
  if (!section_va) {
    std::uint32_t max_va = 0;
    for (const auto& s : secs) {
      max_va = std::max(max_va, s.virtual_address + align_up(std::max(s.virtual_size, s.size_of_raw_data),
                                                             v.section_align));
    }
    section_va = align_up(max_va, v.section_align);
  }

  auto blob = build_rsrc(leaves, section_va);
  const auto raw_size = align_up(static_cast<std::uint32_t>(blob.size()), v.file_align);
  blob.resize(raw_size, 0);

  if (rsrc) {
    const auto old_raw = rsrc->size_of_raw_data;
    const auto old_ptr = rsrc->pointer_to_raw_data;
    if (raw_size <= old_raw) {
      std::fill(v.bytes.begin() + old_ptr, v.bytes.begin() + old_ptr + old_raw,
                static_cast<std::uint8_t>(0));
      std::copy(blob.begin(), blob.end(), v.bytes.begin() + old_ptr);
      rsrc->virtual_size = static_cast<std::uint32_t>(blob.size() ? blob.size() : 1);
      // keep size_of_raw_data
    } else {
      // Append new raw data at end; leave a hole where old .rsrc was.
      const auto new_ptr = align_up(static_cast<std::uint32_t>(v.bytes.size()), v.file_align);
      v.bytes.resize(new_ptr + raw_size, 0);
      std::copy(blob.begin(), blob.end(), v.bytes.begin() + new_ptr);
      rsrc->pointer_to_raw_data = new_ptr;
      rsrc->size_of_raw_data = raw_size;
      rsrc->virtual_size = static_cast<std::uint32_t>(blob.size());
    }
    std::memcpy(v.bytes.data() + v.sections_off + rsrc_index * sizeof(SectionHeader), rsrc,
                sizeof(SectionHeader));
    DataDir dd{section_va, static_cast<std::uint32_t>(blob.size())};
    set_data_dir(v, kDirResource, dd);
    const auto new_image =
        align_up(section_va + align_up(rsrc->virtual_size, v.section_align), v.section_align);
    std::uint32_t cur_image = 0;
    read_at(v.bytes, v.size_of_image_off, cur_image);
    if (new_image > cur_image) {
      std::memcpy(v.bytes.data() + v.size_of_image_off, &new_image, 4);
    }
  } else {
    // Add a .rsrc section.
    const auto new_ptr = align_up(static_cast<std::uint32_t>(v.bytes.size()), v.file_align);
    v.bytes.resize(new_ptr + raw_size, 0);
    std::copy(blob.begin(), blob.end(), v.bytes.begin() + new_ptr);
    SectionHeader sh{};
    std::memcpy(sh.name, ".rsrc\0\0", 8);
    sh.virtual_size = static_cast<std::uint32_t>(blob.size());
    sh.virtual_address = section_va;
    sh.size_of_raw_data = raw_size;
    sh.pointer_to_raw_data = new_ptr;
    sh.characteristics = 0x40000040;  // INIT_DATA | READ
    // Need room in the header for another section.
    const auto new_sec_end = v.sections_off + (v.coff.number_of_sections + 1) * sizeof(SectionHeader);
    std::uint32_t size_of_headers = 0;
    read_at(v.bytes, v.size_of_headers_off, size_of_headers);
    if (new_sec_end > size_of_headers) {
      return Status::fail(ExitCode::Validation,
                          "PE header has no room to add a .rsrc section");
    }
    std::memcpy(v.bytes.data() + v.sections_off + v.coff.number_of_sections * sizeof(SectionHeader),
                &sh, sizeof(sh));
    v.coff.number_of_sections += 1;
    std::memcpy(v.bytes.data() + v.lfanew + 4, &v.coff, sizeof(v.coff));
    DataDir dd{section_va, static_cast<std::uint32_t>(blob.size())};
    set_data_dir(v, kDirResource, dd);
    const auto new_image = align_up(section_va + align_up(sh.virtual_size, v.section_align),
                                    v.section_align);
    std::memcpy(v.bytes.data() + v.size_of_image_off, &new_image, 4);
  }
  return Status::success();
}

#ifdef _WIN32
Expected<std::string> mt_extract(const std::filesystem::path& mt,
                                 const std::filesystem::path& exe,
                                 const std::filesystem::path& out_xml) {
  auto r = run_process(mt, {"-inputresource:" + exe.string() + ";#1", "-out:" + out_xml.string()});
  if (!r) return Expected<std::string>::fail(r.error());
  if (r.value().exit_code != 0) {
    return Expected<std::string>::ok(std::string{});
  }
  std::ifstream in(out_xml, std::ios::binary);
  if (!in) return Expected<std::string>::ok(std::string{});
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return Expected<std::string>::ok(std::move(text));
}

Status mt_embed(const std::filesystem::path& mt, const std::filesystem::path& exe,
                const std::filesystem::path& xml) {
  auto r = run_process(mt, {"-manifest", xml.string(), "-outputresource:" + exe.string() + ";#1"});
  if (!r) return Status::fail(r.code(), r.message());
  if (r.value().exit_code != 0) {
    return Status::fail(ExitCode::Environment,
                        "mt.exe failed: " + r.value().stderr_text + r.value().stdout_text);
  }
  return Status::success();
}
#endif

}  // namespace

Expected<PeInspection> inspect_pe(const std::filesystem::path& path) {
  auto view = parse_pe(path);
  if (!view) return Expected<PeInspection>::fail(view.error());
  PeInspection info;
  info.is_pe = true;
  info.architecture = view.value().arch;
  info.is_dll = view.value().is_dll;
  info.sha256 = sha256_file_hex(path);
  const auto sec = data_dir(view.value(), kDirSecurity);
  info.authenticode_present = sec.va != 0 && sec.size != 0;
  info.authenticode_status = info.authenticode_present ? "present" : "unsigned";

  const auto res = data_dir(view.value(), kDirResource);
  if (res.va && res.size) {
    std::vector<ResLeaf> leaves;
    walk_res(view.value(), res.va, res.va, 0, 0, 0, leaves);
    for (const auto& leaf : leaves) {
      if (leaf.type == kRtManifest && !info.has_embedded_manifest) {
        info.has_embedded_manifest = true;
        info.embedded_manifest.assign(leaf.data.begin(), leaf.data.end());
        // strip UTF-8 BOM
        if (info.embedded_manifest.size() >= 3 &&
            static_cast<unsigned char>(info.embedded_manifest[0]) == 0xef) {
          info.embedded_manifest.erase(0, 3);
        }
      }
      if (leaf.type == kRtVersion && info.file_version.empty()) {
        parse_version_info(leaf.data, info);
      }
    }
  }
  return Expected<PeInspection>::ok(std::move(info));
}

Expected<std::string> patch_embedded_manifest_xml(std::string_view existing_or_empty,
                                                  const MsixIdentityTuple& tuple) {
  return merge_msix_element(existing_or_empty, tuple);
}

Expected<PatchExeResult> patch_exe_identity(const std::filesystem::path& staged_exe,
                                            const PatchExeOptions& options) {
  auto before = inspect_pe(staged_exe);
  if (!before) return Expected<PatchExeResult>::fail(before.error());
  if (before.value().authenticode_present && !options.accept_signature_loss) {
    return Expected<PatchExeResult>::fail(
        ExitCode::SignatureConsent,
        "staged EXE is signed; pass --accept-signature-loss to continue");
  }

  if (before.value().authenticode_present) {
    auto view = parse_pe(staged_exe);
    if (!view) return Expected<PatchExeResult>::fail(view.error());
    strip_authenticode(view.value());
    if (!write_file(staged_exe, view.value().bytes)) {
      return Expected<PatchExeResult>::fail(ExitCode::Internal,
                                            "failed to strip Authenticode signature");
    }
  }

  auto merged = patch_embedded_manifest_xml(before.value().embedded_manifest, options.identity);
  if (!merged) return Expected<PatchExeResult>::fail(merged.error());

  bool used_mt = false;
#ifdef _WIN32
  std::filesystem::path mt = options.mt_exe;
  if (mt.empty()) {
    auto found = locate_mt_exe();
    if (found) mt = found.value();
  }
  if (!mt.empty()) {
    const auto tmp_dir = staged_exe.parent_path() / ".repackager-mt";
    std::error_code ec;
    std::filesystem::create_directories(tmp_dir, ec);
    const auto xml_path = tmp_dir / "embedded.manifest";
    {
      std::ofstream out(xml_path, std::ios::binary | std::ios::trunc);
      out << merged.value();
    }
    auto st = mt_embed(mt, staged_exe, xml_path);
    if (!st) return Expected<PatchExeResult>::fail(st.code, st.message);
    used_mt = true;
    std::filesystem::remove_all(tmp_dir, ec);
  }
#endif
  if (!used_mt) {
    auto view = parse_pe(staged_exe);
    if (!view) return Expected<PatchExeResult>::fail(view.error());
    auto st = embed_manifest_portable(view.value(), merged.value());
    if (!st) return Expected<PatchExeResult>::fail(st.code, st.message);
    if (!write_file(staged_exe, view.value().bytes)) {
      return Expected<PatchExeResult>::fail(ExitCode::Internal,
                                            "failed to rewrite staged EXE");
    }
  }

  auto after = inspect_pe(staged_exe);
  if (!after) return Expected<PatchExeResult>::fail(after.error());
  if (!after.value().has_embedded_manifest) {
    return Expected<PatchExeResult>::fail(ExitCode::Validation,
                                          "re-extract found no embedded manifest");
  }
  auto tuple = extract_msix_tuple(after.value().embedded_manifest);
  if (!tuple) return Expected<PatchExeResult>::fail(tuple.error());
  if (!msix_tuple_matches(tuple.value(), options.identity)) {
    return Expected<PatchExeResult>::fail(
        ExitCode::Validation,
        "re-extracted <msix> identity does not match the requested tuple");
  }

  PatchExeResult result;
  result.written_manifest = after.value().embedded_manifest;
  result.verified = tuple.take();
  result.signature_stripped = before.value().authenticode_present;
  return Expected<PatchExeResult>::ok(std::move(result));
}

}  // namespace repackager
