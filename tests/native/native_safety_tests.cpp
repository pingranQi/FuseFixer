#include "elf_parser.hpp"
#include "utf8_utils.hpp"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
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

void testUtf16Conversion() {
    std::string utf8;
    const char16_t ascii_and_bmp[] = u"A\u03A9";
    assert(utf16ToStandardUtf8(ascii_and_bmp, 2, &utf8) == 0);
    assert(utf8 == "A\xCE\xA9");

    const char16_t supplementary[] = u"\U0001F600";
    assert(utf16ToStandardUtf8(supplementary, 2, &utf8) == 0);
    assert(utf8 == "\xF0\x9F\x98\x80");

    const char16_t unpaired_high[] = {0xD800};
    const char16_t unpaired_low[] = {0xDC00};
    const char16_t mismatched_pair[] = {0xD800, u'A'};
    const char16_t embedded_nul[] = {u'a', 0, u'b'};
    const char16_t max_code_point[] = {0xDBFF, 0xDFFF};
    assert(utf16ToStandardUtf8(unpaired_high, 1, &utf8) == EILSEQ);
    assert(utf8.empty());
    assert(utf16ToStandardUtf8(unpaired_low, 1, &utf8) == EILSEQ);
    assert(utf8.empty());
    assert(utf16ToStandardUtf8(mismatched_pair, 2, &utf8) == EILSEQ);
    assert(utf8.empty());
    assert(utf16ToStandardUtf8(embedded_nul, 3, &utf8) == EINVAL);
    assert(utf8.empty());
    assert(utf16ToStandardUtf8(max_code_point, 2, &utf8) == 0);
    assert(utf8 == "\xF4\x8F\xBF\xBF");
    assert(utf16ToStandardUtf8(nullptr, 1, &utf8) == EINVAL);
    assert(utf8.empty());
}

void testXz() {
    static constexpr char valid_hex[] =
        "fd377a585a000004e6d6b4460200210116000000742fe5a301002046757365"
        "4669786572206e617469766520585a2074657374207061796c6f61640a00"
        "000000f85e45f9fe42164f00013921cf286b621fb6f37d010000000004595a";
    std::vector<uint8_t> valid;
    for (size_t i = 0; i + 1 < sizeof(valid_hex); i += 2) {
        const auto byte = static_cast<uint8_t>(
                std::strtoul(std::string(valid_hex + i, 2).c_str(), nullptr, 16));
        valid.push_back(byte);
    }
    const auto decoded = elf_parser::testing::DecompressXz(valid.data(), valid.size());
    const std::string expected = "FuseFixer native XZ test payload\n";
    assert(std::string(decoded.begin(), decoded.end()) == expected);
    assert(elf_parser::testing::DecompressXz(valid.data(), valid.size() - 8).empty());
    const uint8_t garbage[] = {0, 1, 2, 3, 4, 5};
    assert(elf_parser::testing::DecompressXz(garbage, sizeof(garbage)).empty());
    assert(elf_parser::testing::DecompressXz(nullptr, 0).empty());
    for (size_t size = 1; size < 256; ++size) {
        std::vector<uint8_t> malformed(size);
        for (size_t i = 0; i < size; ++i)
            malformed[i] = static_cast<uint8_t>((i * 73 + size * 29) & 0xff);
        assert(elf_parser::testing::DecompressXz(
                malformed.data(), malformed.size()).empty());
    }
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

uint32_t testSysvHash(std::string_view name) {
    uint32_t hash = 0;
    for (unsigned char ch : name) {
        hash = (hash << 4) + ch;
        const uint32_t high = hash & 0xF0000000U;
        hash ^= high;
        hash ^= high >> 24;
    }
    return hash;
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

    auto bad_phdr = bytes;
    auto *bad_phdr_ehdr = reinterpret_cast<ElfW(Ehdr) *>(bad_phdr.data());
    bad_phdr_ehdr->e_phoff = static_cast<ElfW(Off)>(bad_phdr.size() - 1);
    auto bad_phdr_path = writeTemp(bad_phdr, "-bad-phdr");
    elf_parser::Elf bad_phdr_elf;
    assert(!bad_phdr_elf.InitFromFile(bad_phdr_path, 0, true));
    unlink(bad_phdr_path.c_str());

    auto bad_phentsize = bytes;
    auto *bad_phentsize_ehdr = reinterpret_cast<ElfW(Ehdr) *>(bad_phentsize.data());
    if (bad_phentsize_ehdr->e_phnum != 0) {
        bad_phentsize_ehdr->e_phentsize = 1;
        auto bad_phentsize_path = writeTemp(bad_phentsize, "-bad-phentsize");
        elf_parser::Elf bad_phentsize_elf;
        assert(!bad_phentsize_elf.InitFromFile(bad_phentsize_path, 0, true));
        unlink(bad_phentsize_path.c_str());
    }

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

    if (changed) {
        auto bad_chain = bytes;
        auto *bad_chain_sections = reinterpret_cast<ElfW(Shdr) *>(
                bad_chain.data() + original_shoff);
        for (uint16_t i = 0; i < original_shnum; ++i) {
            if (bad_chain_sections[i].sh_type != SHT_GNU_HASH) continue;
            auto *words = reinterpret_cast<ElfW(Word) *>(
                    bad_chain.data() + bad_chain_sections[i].sh_offset);
            const uint32_t bucket_count = words[0];
            const uint32_t bloom_count = words[2];
            assert(bucket_count != 0);
            auto *buckets = reinterpret_cast<uint32_t *>(
                    words + 4 + (static_cast<size_t>(bloom_count) *
                                sizeof(ElfW(Addr)) / sizeof(ElfW(Word))));
            buckets[0] = UINT32_MAX;
            break;
        }
        auto bad_chain_path = writeTemp(bad_chain, "-bad-gnu-chain");
        elf_parser::Elf bad_chain_elf;
        assert(!bad_chain_elf.InitFromFile(bad_chain_path, 0, true));
        unlink(bad_chain_path.c_str());
    }

    // Oversized GNU hash dimensions must be rejected before pointer math.
    auto bad_gnu_dimensions = bytes;
    auto *gnu_dim_sections = reinterpret_cast<ElfW(Shdr) *>(
            bad_gnu_dimensions.data() + original_shoff);
    bool has_gnu_dimensions = false;
    for (uint16_t i = 0; i < original_shnum; ++i) {
        if (gnu_dim_sections[i].sh_type != SHT_GNU_HASH) continue;
        auto *words = reinterpret_cast<ElfW(Word) *>(
                bad_gnu_dimensions.data() + gnu_dim_sections[i].sh_offset);
        words[0] = UINT32_MAX;
        has_gnu_dimensions = true;
        break;
    }
    if (has_gnu_dimensions) {
        auto bad_gnu_path = writeTemp(bad_gnu_dimensions, "-bad-gnu-dimensions");
        elf_parser::Elf bad_gnu_elf;
        assert(!bad_gnu_elf.InitFromFile(bad_gnu_path, 0, true));
        unlink(bad_gnu_path.c_str());
    }

    auto bad_sysv_dimensions = bytes;
    auto *sysv_dim_sections = reinterpret_cast<ElfW(Shdr) *>(
            bad_sysv_dimensions.data() + original_shoff);
    bool has_sysv_dimensions = false;
    for (uint16_t i = 0; i < original_shnum; ++i) {
        if (sysv_dim_sections[i].sh_type != SHT_HASH) continue;
        auto *words = reinterpret_cast<ElfW(Word) *>(
                bad_sysv_dimensions.data() + sysv_dim_sections[i].sh_offset);
        words[0] = UINT32_MAX;
        has_sysv_dimensions = true;
        break;
    }
    if (has_sysv_dimensions) {
        auto bad_sysv_path = writeTemp(bad_sysv_dimensions, "-bad-sysv-dimensions");
        elf_parser::Elf bad_sysv_elf;
        assert(!bad_sysv_elf.InitFromFile(bad_sysv_path, 0, true));
        unlink(bad_sysv_path.c_str());
    }

    // Exercise SysV chain-index guards independently of GNU hash lookup.
    auto bad_sysv = bytes;
    auto *sysv_sections = reinterpret_cast<ElfW(Shdr) *>(
            bad_sysv.data() + original_shoff);
    bool has_sysv = false;
    for (uint16_t i = 0; i < original_shnum; ++i) {
        if (sysv_sections[i].sh_type == SHT_GNU_HASH)
            sysv_sections[i].sh_type = SHT_NULL;
        if (sysv_sections[i].sh_type != SHT_HASH) continue;
        auto *words = reinterpret_cast<ElfW(Word) *>(
                bad_sysv.data() + sysv_sections[i].sh_offset);
        assert(words[0] != 0 && words[1] > 1);
        words[2] = UINT32_MAX;
        has_sysv = true;
        break;
    }
    if (has_sysv) {
        auto bad_sysv_path = writeTemp(bad_sysv, "-bad-sysv-chain");
        elf_parser::Elf bad_sysv_elf;
        assert(!bad_sysv_elf.InitFromFile(bad_sysv_path, 0, true));
        unlink(bad_sysv_path.c_str());
    }

    // Exercise the dynamic parser against a real mapped shared object.
    void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    assert(handle != nullptr);
    MappedElfRange libc_range;
    assert(dl_iterate_phdr(findLibcRange, &libc_range) == 1);
    assert(libc_range.base != 0 && libc_range.size != 0);
    {
        elf_parser::Elf dynamic_elf;
        assert(dynamic_elf.InitFromMemory(
                reinterpret_cast<void *>(libc_range.base), true, libc_range.size));
        assert(dynamic_elf.getSym("malloc") != nullptr);
    }
    // The parser must not unmap a loader-owned image when it is destroyed.
    void *allocation_after_parse = std::malloc(32);
    assert(allocation_after_parse != nullptr);
    std::free(allocation_after_parse);
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
    testUtf16Conversion();
    testXz();
    testElfFiles(argc == 2 ? argv[1] : argv[0]);
    std::cout << "FuseFixer native safety tests passed\n";
    return 0;
}
