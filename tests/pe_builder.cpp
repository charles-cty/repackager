#include "pe_builder.hpp"

#include <cstring>
#include <fstream>

namespace repackager::test {
namespace {

#pragma pack(push, 1)
struct Dos {
  std::uint16_t e_magic = 0x5A4D;
  std::uint16_t pad[29]{};
  std::uint32_t e_lfanew = 0x80;
};
struct Coff {
  std::uint16_t machine;
  std::uint16_t sections;
  std::uint32_t timedate = 0;
  std::uint32_t sym = 0;
  std::uint32_t nsym = 0;
  std::uint16_t opt_size;
  std::uint16_t chars;
};
struct DataDir {
  std::uint32_t va = 0;
  std::uint32_t size = 0;
};
struct Opt64 {
  std::uint16_t magic = 0x20b;
  std::uint8_t major_linker = 14;
  std::uint8_t minor_linker = 0;
  std::uint32_t size_of_code = 0x200;
  std::uint32_t size_of_init = 0;
  std::uint32_t size_of_uninit = 0;
  std::uint32_t entry = 0x1000;
  std::uint32_t base_of_code = 0x1000;
  std::uint64_t image_base = 0x140000000ull;
  std::uint32_t section_align = 0x1000;
  std::uint32_t file_align = 0x200;
  std::uint16_t os_major = 6;
  std::uint16_t os_minor = 0;
  std::uint16_t img_major = 0;
  std::uint16_t img_minor = 0;
  std::uint16_t sub_major = 6;
  std::uint16_t sub_minor = 0;
  std::uint32_t win32 = 0;
  std::uint32_t size_of_image = 0x3000;
  std::uint32_t size_of_headers = 0x200;
  std::uint32_t checksum = 0;
  std::uint16_t subsystem = 3;  // console
  std::uint16_t dll_chars = 0x160;
  std::uint64_t stack_reserve = 0x100000;
  std::uint64_t stack_commit = 0x1000;
  std::uint64_t heap_reserve = 0x100000;
  std::uint64_t heap_commit = 0x1000;
  std::uint32_t loader_flags = 0;
  std::uint32_t rva_count = 16;
  DataDir dirs[16]{};
};
struct Sec {
  char name[8]{};
  std::uint32_t vsize = 0;
  std::uint32_t va = 0;
  std::uint32_t raw_size = 0;
  std::uint32_t raw_ptr = 0;
  std::uint32_t rel = 0;
  std::uint32_t ln = 0;
  std::uint16_t nrel = 0;
  std::uint16_t nln = 0;
  std::uint32_t chars = 0;
};
struct ResDir {
  std::uint32_t characteristics = 0;
  std::uint32_t timedate = 0;
  std::uint16_t major = 0;
  std::uint16_t minor = 0;
  std::uint16_t named = 0;
  std::uint16_t ids = 0;
};
struct ResEntry {
  std::uint32_t name = 0;
  std::uint32_t offset = 0;
};
struct ResData {
  std::uint32_t rva = 0;
  std::uint32_t size = 0;
  std::uint32_t cp = 0;
  std::uint32_t reserved = 0;
};
#pragma pack(pop)

std::uint32_t align(std::uint32_t v, std::uint32_t a) { return (v + a - 1) & ~(a - 1); }

}  // namespace

bool write_minimal_pe(const std::filesystem::path& path, const PeBuildOptions& options) {
  const bool has_manifest = !options.manifest.empty();
  const int nsec = has_manifest ? 2 : 1;

  Dos dos{};
  Coff coff{};
  coff.machine = options.machine;
  coff.sections = static_cast<std::uint16_t>(nsec);
  coff.opt_size = sizeof(Opt64);
  coff.chars = 0x0002 | 0x0102;  // EXECUTABLE | 32BIT_MACHINE-ish for amd64
  Opt64 opt{};
  opt.size_of_headers = 0x400;
  opt.size_of_image = has_manifest ? 0x3000 : 0x2000;

  Sec text{};
  std::memcpy(text.name, ".text", 5);
  text.vsize = 0x20;
  text.va = 0x1000;
  text.raw_size = 0x200;
  text.raw_ptr = 0x400;
  text.chars = 0x60000020;

  std::vector<std::uint8_t> rsrc_raw;
  Sec rsrc{};
  if (has_manifest) {
    const auto& xml = options.manifest;
    // Simple resource tree: type 24 -> id 1 -> lang 0x409
    const std::uint32_t section_va = 0x2000;
    const std::uint32_t dir_root = 0;
    const std::uint32_t dir_type = sizeof(ResDir) + sizeof(ResEntry);
    const std::uint32_t dir_id = dir_type + sizeof(ResDir) + sizeof(ResEntry);
    const std::uint32_t data_ent = dir_id + sizeof(ResDir) + sizeof(ResEntry);
    const std::uint32_t blob = data_ent + sizeof(ResData);
    rsrc_raw.assign(blob + xml.size() + 16, 0);
    auto put_dir = [&](std::uint32_t off, std::uint16_t ids) {
      ResDir d{};
      d.ids = ids;
      std::memcpy(rsrc_raw.data() + off, &d, sizeof(d));
    };
    put_dir(dir_root, 1);
    ResEntry e1{24, 0x80000000u | dir_type};
    std::memcpy(rsrc_raw.data() + sizeof(ResDir), &e1, sizeof(e1));
    put_dir(dir_type, 1);
    ResEntry e2{1, 0x80000000u | dir_id};
    std::memcpy(rsrc_raw.data() + dir_type + sizeof(ResDir), &e2, sizeof(e2));
    put_dir(dir_id, 1);
    ResEntry e3{0x0409, data_ent};
    std::memcpy(rsrc_raw.data() + dir_id + sizeof(ResDir), &e3, sizeof(e3));
    ResData rd{};
    rd.rva = section_va + blob;
    rd.size = static_cast<std::uint32_t>(xml.size());
    std::memcpy(rsrc_raw.data() + data_ent, &rd, sizeof(rd));
    if (!xml.empty()) {
      std::memcpy(rsrc_raw.data() + blob, xml.data(), xml.size());
    }
    rsrc_raw.resize(align(static_cast<std::uint32_t>(rsrc_raw.size()), 0x200), 0);

    std::memcpy(rsrc.name, ".rsrc", 5);
    rsrc.vsize = static_cast<std::uint32_t>(rsrc_raw.size());
    rsrc.va = 0x2000;
    rsrc.raw_size = static_cast<std::uint32_t>(rsrc_raw.size());
    rsrc.raw_ptr = 0x600;
    rsrc.chars = 0x40000040;
    opt.dirs[2].va = 0x2000;
    opt.dirs[2].size = rsrc.vsize;
  }

  std::vector<std::uint8_t> file(0x400 + 0x200 + rsrc_raw.size() + (options.authenticode ? 128 : 0),
                                 0);
  std::memcpy(file.data(), &dos, sizeof(dos));
  std::uint32_t pe = 0x00004550;
  std::memcpy(file.data() + 0x80, &pe, 4);
  std::memcpy(file.data() + 0x84, &coff, sizeof(coff));
  std::memcpy(file.data() + 0x84 + sizeof(coff), &opt, sizeof(opt));
  const auto sec_off = 0x84 + sizeof(coff) + sizeof(opt);
  std::memcpy(file.data() + sec_off, &text, sizeof(text));
  if (has_manifest) std::memcpy(file.data() + sec_off + sizeof(text), &rsrc, sizeof(rsrc));

  // tiny "code"
  file[0x400] = 0xC3;  // ret
  if (has_manifest) {
    std::memcpy(file.data() + 0x600, rsrc_raw.data(), rsrc_raw.size());
  }

  if (options.authenticode) {
    // Certificate table: file offset + size in data directory 4.
    const auto cert_off = static_cast<std::uint32_t>(file.size() - 128);
    // Rewrite optional header dir 4. VA for security dir is a file offset.
    Opt64 opt2;
    std::memcpy(&opt2, file.data() + 0x84 + sizeof(coff), sizeof(opt2));
    opt2.dirs[4].va = cert_off;
    opt2.dirs[4].size = 128;
    std::memcpy(file.data() + 0x84 + sizeof(coff), &opt2, sizeof(opt2));
    // WIN_CERTIFICATE-like blob
    file[cert_off] = 128;
    file[cert_off + 4] = 0x00;
    file[cert_off + 5] = 0x02;  // WIN_CERT_REVISION_2_0
    file[cert_off + 6] = 0x02;  // WIN_CERT_TYPE_PKCS_SIGNED_DATA
  }

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return false;
  out.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
  return static_cast<bool>(out);
}

}  // namespace repackager::test
