#include "elf_parser.hpp"
#include "utf8_utils.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <link.h>
#include <string>
#include <vector>
#include <unistd.h>

namespace {
std::string writeTemp(const std::vector<uint8_t> &bytes, const char *suffix) {
    std::string path = std::string("/tmp/fusefixer-") +
            std::to_string(getpid()) + suffix;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    file.close();
    return path;
}

std::vector<uint8_t> readFile(const char *path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}

void testUtf8() {
    assert(svcasecmp_fix("A\xE2\x80\x8B" "B", "ab") == 0);
    const std::string malformed("\xF0\x28\x8C\x28", 4);
    assert(svcasecmp_fix(malformed, malformed) == 0);
    std::string preserved = malformed + "\xE2\x80\x8B";
    assert(has_default_ignorable_code_point(preserved));
    remove_default_ignorable_code_point(preserved);
    assert(preserved == malformed);
    assert(strcasecmp_fix("Fuse", "fUSE") == 0);
    assert(strcasecmp_fix(nullptr, nullptr) == 0);
}

void testXz() {
    static constexpr uint8_t valid[] = {
        0xfd,0x37,0x7a,0x58,0x5a,0x00,0x00,0x04,0xe6,0xd6,0xb4,0x46,
        0x02,0x00,0x21,0x01,0x16,0x00,0x00,0x00,0x74,0x2f,0xe5,0xa3,
        0x01,0x00,0x20,0x46,0x75,0x73,0x65,0x46,0x69,0x78,0x65,0x72,
        0x20,0x6e,0x61,0x74,0x69,0x76,0x65,0x20,0x58,0x5a,0x20,0x74,
        0x65,0x73,0x74,0x20,0x70,0x61,0x79,0x6c,0x6f,0x61,0x64,0x0a,
        0x00,0x00,0x00,0x00,0xf8,0x5e,0x45,0xf9,0xfe,0x42,0x16,0x4f,
        0x00,0x01,0x39,0x21,0xcf,0x28,0x6b,0x62,0x1f,0xb6,0xf3,0x7d,
        0x01,0x00,0x00,0x00,0x00,0x04,0x59,0x5a
    };
    const auto decoded = elf_parser::testing::DecompressXz(valid, sizeof(valid));
    const std::string expected = "FuseFixer native XZ test payload\n";
    assert(std::string(decoded.begin(), decoded.end()) == expected);
    assert(elf_parser::testing::DecompressXz(valid, sizeof(valid) - 8).empty());
    const uint8_t garbage[] = {0, 1, 2, 3, 4, 5};
    assert(elf_parser::testing::DecompressXz(garbage, sizeof(garbage)).empty());
    assert(elf_parser::testing::DecompressXz(nullptr, 0).empty());
}

struct MappedElfRange {
    uintptr_t base = 0;
    size_t size = 0;
};

int findLibcRange(dl_phdr_info *info, size_t, void *opaque) {
    if (!info->dlpi_name || std::strstr(info->dlpi_name, "libc.so.6") == nullptr)
        return 0;
    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        const auto &phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD) continue;
        min_vaddr = std::min(min_vaddr, static_cast<uintptr_t>(phdr.p_vaddr));
        max_vaddr = std::max(max_vaddr,
                static_cast<uintptr_t>(phdr.p_vaddr + phdr.p_memsz));
    }
    if (min_vaddr == UINTPTR_MAX || max_vaddr <= min_vaddr) return 0;
    auto *range = static_cast<MappedElfRange *>(opaque);
    range->base = static_cast<uintptr_t>(info->dlpi_addr) + min_vaddr;
    range->size = max_vaddr - min_vaddr;
    return 1;
}

void testElfFiles(const char *self) {
    elf_parser::Elf good;
    assert(good.InitFromFile(self, 0, true));
    const auto bytes = readFile(self);
    assert(bytes.size() > sizeof(ElfW(Ehdr)));

    const auto *original_ehdr =
            reinterpret_cast<const ElfW(Ehdr) *>(bytes.data());
    const ElfW(Off) original_shoff = original_ehdr->e_shoff;
    const uint16_t original_shnum = original_ehdr->e_shnum;
    auto bad_header = bytes;
    auto *bad_ehdr = reinterpret_cast<ElfW(Ehdr) *>(bad_header.data());
    bad_ehdr->e_shoff = static_cast<ElfW(Off)>(bad_header.size() - 1);
    auto bad_header_path = writeTemp(bad_header, "-bad-header");
    elf_parser::Elf bad_header_elf;
    assert(!bad_header_elf.InitFromFile(bad_header_path, 0, true));
    unlink(bad_header_path.c_str());

    auto bad_section = bytes;
    auto *section_header = reinterpret_cast<ElfW(Shdr) *>(
            bad_section.data() + original_shoff);
    bool changed = false;
    for (uint16_t i = 0; i < original_shnum; ++i) {
        if (section_header[i].sh_type == SHT_GNU_HASH) {
            section_header[i].sh_offset = bad_section.size() - 1;
            changed = true;
            break;
        }
    }
    if (changed) {
        auto bad_section_path = writeTemp(bad_section, "-bad-gnu-hash");
        elf_parser::Elf bad_section_elf;
        assert(!bad_section_elf.InitFromFile(bad_section_path, 0, true));
        unlink(bad_section_path.c_str());
    }

    // Exercise the dynamic parser against a real mapped shared object.
    void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    assert(handle != nullptr);
    MappedElfRange libc_range;
    assert(dl_iterate_phdr(findLibcRange, &libc_range) == 1);
    assert(libc_range.base != 0 && libc_range.size != 0);
    elf_parser::Elf dynamic_elf;
    assert(dynamic_elf.InitFromMemory(
            reinterpret_cast<void *>(libc_range.base), true, libc_range.size));
    assert(dynamic_elf.getSym("malloc") != nullptr);
    dlclose(handle);

    // Deterministic malformed-input smoke fuzzing: arbitrary short files must
    // be rejected without reading outside their file-backed extent.
    for (size_t size = 0; size < 512; ++size) {
        std::vector<uint8_t> fuzz(size);
        for (size_t i = 0; i < size; ++i)
            fuzz[i] = static_cast<uint8_t>((i * 131 + size * 17) & 0xff);
        auto fuzz_path = writeTemp(fuzz, "-fuzz");
        elf_parser::Elf fuzz_elf;
        (void) fuzz_elf.InitFromFile(fuzz_path, 0, true);
        unlink(fuzz_path.c_str());
    }
}
} // namespace

int main(int argc, char **argv) {
    assert(argc == 1 || argc == 2);
    testUtf8();
    testXz();
    testElfFiles(argc == 2 ? argv[1] : argv[0]);
    std::cout << "FuseFixer native safety tests passed\n";
    return 0;
}
