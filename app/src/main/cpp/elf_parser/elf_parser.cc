#include "include/elf_parser.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "xz.h"
#include "logging.h"

#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE(x) (((unsigned int)x) & 0xf)
#endif

#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    //.rel.dyn
#define ELF_R_GENERIC_ABS R_ARM_ABS32            //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_X86_64_64
#endif

#if defined(__LP64__)
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

using namespace std::string_view_literals;

namespace {
    bool rangeWithin(size_t total, uint64_t offset, uint64_t length) {
        return offset <= total && length <= static_cast<uint64_t>(total) - offset;
    }

    bool validateSysvHash(const ElfW(Word) *raw, size_t available_words) {
        if (!raw || available_words < 2) return false;
        const size_t bucket_count = raw[0];
        const size_t symbol_count = raw[1];
        if (bucket_count == 0 || symbol_count == 0 ||
            bucket_count > SIZE_MAX - 2 ||
            symbol_count > SIZE_MAX - 2 - bucket_count) return false;
        const size_t required_words = 2 + bucket_count + symbol_count;
        if (required_words > available_words) return false;
        for (size_t i = 0; i < bucket_count + symbol_count; ++i) {
            const uint32_t index = raw[2 + i];
            if (index >= symbol_count && index != STN_UNDEF) return false;
        }
        return true;
    }

    bool VerifyElfHeader(ElfW(Ehdr) *header) {
        if (0 != memcmp(header->e_ident, ELFMAG, SELFMAG))
            return false;

#if defined(__LP64__)
        if (ELFCLASS64 != header->e_ident[EI_CLASS])
            return false;
#else
        if (ELFCLASS32 != header->e_ident[EI_CLASS])
          return false;
#endif
        // check endian (little/big)
        if (ELFDATA2LSB != header->e_ident[EI_DATA])
            return false;

        // check version
        if (EV_CURRENT != header->e_ident[EI_VERSION])
            return false;

        // check type
        if (ET_EXEC != header->e_type && ET_DYN != header->e_type)
            return false;

        // check machine
#if defined(__arm__)
        if (EM_ARM != header->e_machine)
          return false;
#elif defined(__aarch64__)
        if (EM_AARCH64 != header->e_machine)
          return false;
#elif defined(__i386__)
        if (EM_386 != header->e_machine)
          return false;
#elif defined(__x86_64__)
        if (EM_X86_64 != header->e_machine)
            return false;
#else
        return false;
#endif
        // check version
        if (EV_CURRENT != header->e_version)
            return false;

        return true;
    }

    std::tuple<uintptr_t, size_t> OpenLibrary(const std::string_view path, size_t file_off) {
        const std::string path_string{path};
        int fd = open(path_string.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            PLOGE("elf_parser: open %s", path_string.c_str());
            return {0, 0};
        }

        struct stat st{};
        if (fstat(fd, &st) < 0) {
            PLOGE("elf_parser: stat %s", path_string.c_str());
            close(fd);
            return {0, 0};
        }
        if (st.st_size <= 0 || file_off > static_cast<uint64_t>(st.st_size)) {
            LOGE("elf_parser: invalid file offset %zu for size %lld",
                 file_off, static_cast<long long>(st.st_size));
            close(fd);
            return {0, 0};
        }
        const long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0 || file_off % static_cast<size_t>(page_size) != 0) {
            LOGE("elf_parser: unaligned file offset %zu", file_off);
            close(fd);
            return {0, 0};
        }
        const size_t sz = static_cast<size_t>(st.st_size) - file_off;
        if (sz == 0) {
            LOGE("elf_parser: empty ELF image");
            close(fd);
            return {0, 0};
        }
        void* mapped = mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, file_off);
        close(fd);
        if (mapped == MAP_FAILED) {
            PLOGE("elf_parser: mmap %s", path_string.c_str());
            return {0, 0};
        }
        return {reinterpret_cast<uintptr_t>(mapped), sz};
    }

    template<typename T>
    inline constexpr auto offsetOf(ElfW(Ehdr) *head, ElfW(Off) off) {
        return reinterpret_cast<std::conditional_t<std::is_pointer_v<T>, T, T *>>(
                reinterpret_cast<uintptr_t>(head) + off);
    }

    template <typename T>
    inline constexpr auto setByOffset(T &ptr, ElfW(Addr) base, ElfW(Addr) bias, ElfW(Addr) off) {
        if (auto val = bias + off; val > base) {
            ptr = reinterpret_cast<T>(val);
            return true;
        }
        ptr = 0;
        return false;
    }

    std::vector<uint8_t> unxz(const uint8_t *data, size_t size) {
        std::vector<uint8_t> out;
        if (!data || size == 0) return out;
        uint8_t buf[8192];
        xz_crc32_init();
        xz_crc64_init();
        struct xz_dec* dec = xz_dec_init(XZ_DYNALLOC, 1 << 26);
        if (!dec) {
            LOGE("unxz: decoder initialization failed");
            return out;
        }
        struct XzDecoderGuard {
            struct xz_dec* decoder;
            ~XzDecoderGuard() {
                if (decoder) xz_dec_end(decoder);
            }
        } decoder_guard{dec};

        constexpr size_t kMaxDebugDataSize = 128U * 1024U * 1024U;
        struct xz_buf b = {.in = data,
                .in_pos = 0,
                .in_size = size,
                .out = buf,
                .out_pos = 0,
                .out_size = sizeof(buf)};
        while (true) {
            // Multi-call XZ decoding may still have buffered output after all
            // input bytes have been consumed. Keep draining until the decoder
            // reports STREAM_END or a genuine error/no-progress condition.
            const size_t in_pos_before = b.in_pos;
            const auto ret = xz_dec_run(dec, &b);
            const size_t produced = b.out_pos;
            if (produced != 0) {
                if (produced > kMaxDebugDataSize - out.size()) {
                    LOGE("unxz: expanded debug data exceeds %zu bytes",
                         kMaxDebugDataSize);
                    out.clear();
                    return out;
                }
                out.insert(out.end(), buf, buf + produced);
            }
            b.out_pos = 0;

            if (ret == XZ_STREAM_END) {
                break;
            }
            if (ret != XZ_OK) {
                LOGE("unxz error: %d (input %zu/%zu)", ret, b.in_pos, b.in_size);
                out.clear();
                return out;
            }
            // XZ_OK must make forward progress. Without this guard, a
            // truncated stream can spin forever once all input is consumed.
            if (produced == 0 && b.in_pos == in_pos_before) {
                LOGE("unxz: decoder made no progress (input %zu/%zu)",
                     b.in_pos, b.in_size);
                out.clear();
                return out;
            }
        }
        return out;
    }
} // namespace

#ifdef FUSEFIXER_ENABLE_TEST_API
namespace elf_parser::testing {
    std::vector<uint8_t> DecompressXz(const uint8_t *data, size_t size) {
        if (!data && size != 0) return {};
        return unxz(data, size);
    }
}
#endif

namespace elf_parser {
    bool Elf::ContainsRuntimeRange(uintptr_t address, size_t size) const {
        if (size == 0 || address > UINTPTR_MAX - size) return false;
        for (const auto &[start, length] : load_ranges_) {
            if (address >= start && address - start <= length &&
                size <= length - (address - start)) return true;
        }
        return false;
    }

    size_t Elf::RuntimeRemaining(uintptr_t address) const {
        for (const auto &[start, length] : load_ranges_) {
            if (address >= start && address - start < length) {
                return length - static_cast<size_t>(address - start);
            }
        }
        return 0;
    }

    bool Elf::ValidateGnuHash(uint32_t *buckets, size_t bucket_count,
                              uint32_t *chains, size_t chain_words) {
        if (!buckets || !chains || bucket_count == 0 || chain_words == 0 ||
            chain_words > UINT32_MAX ||
            gnu_symndx_ > UINT32_MAX - chain_words) return false;
        size_t max_symbol = gnu_symndx_;
        size_t total_work = 0;
        for (size_t i = 0; i < bucket_count; ++i) {
            const uint32_t first = buckets[i];
            if (first == 0) continue;
            if (first < gnu_symndx_) return false;
            size_t chain_index = static_cast<size_t>(first - gnu_symndx_);
            if (chain_index >= chain_words) return false;
            size_t steps = 0;
            while (chain_index < chain_words) {
                if (++total_work > chain_words) return false;
                const uint32_t value = chains[chain_index];
                ++steps;
                if (value & 1U) break;
                ++chain_index;
            }
            if (chain_index >= chain_words) return false;
            const uint64_t symbol_end = static_cast<uint64_t>(first) + steps;
            if (symbol_end > UINT32_MAX) return false;
            max_symbol = std::max(max_symbol, static_cast<size_t>(symbol_end));
        }
        dynsym_count_ = std::max(dynsym_count_, max_symbol);
        gnu_chain_count_ = chain_words;
        return true;
    }

    bool Elf::Init(uintptr_t load_base, uintptr_t parse_base, size_t size) {
        if (parse_base == 0 || (size != 0 && size < sizeof(ElfW(Ehdr)))) {
            LOGE("invalid ELF input");
            return false;
        }

        load_base_ = load_base;
        parse_base_ = parse_base;
        parse_size_ = size;
        auto header = reinterpret_cast<ElfW(Ehdr) *>(parse_base);
        if (!VerifyElfHeader(header) || header->e_ehsize != sizeof(ElfW(Ehdr))) {
            LOGE("verify ELF header failed");
            return false;
        }
        if (header->e_phnum != 0 &&
            (header->e_phentsize != sizeof(ElfW(Phdr)) ||
             (size != 0 && !rangeWithin(size, header->e_phoff,
                 static_cast<uint64_t>(header->e_phnum) * sizeof(ElfW(Phdr)))))) {
            LOGE("invalid ELF program header table");
            return false;
        }
        if (!for_dynamic_ && header->e_shnum != 0 &&
            (header->e_shentsize != sizeof(ElfW(Shdr)) ||
             (size != 0 && !rangeWithin(size, header->e_shoff,
                 static_cast<uint64_t>(header->e_shnum) * sizeof(ElfW(Shdr)))))) {
            LOGE("invalid ELF section header table");
            return false;
        }
        header_ = header;

        if (header->e_phnum != 0) {
            auto *phdr = reinterpret_cast<ElfW(Phdr) *>(parse_base + header->e_phoff);
            for (uint16_t i = 0; i < header->e_phnum; ++i) {
                const auto &entry = phdr[i];
                if (entry.p_type == PT_LOAD)
                    vaddr_min_ = vaddr_min_ < entry.p_vaddr
                            ? vaddr_min_ : static_cast<uintptr_t>(entry.p_vaddr);
                else if (entry.p_type == PT_DYNAMIC) {
                    if (entry.p_memsz > SIZE_MAX) return false;
                    dynamic_off_ = entry.p_vaddr;
                    dynamic_size_ = static_cast<size_t>(entry.p_memsz);
                }
            }
            if (load_base_ != 0 && vaddr_min_ != UINTPTR_MAX) {
                if (load_base_ < vaddr_min_) return false;
                const uintptr_t bias = load_base_ - vaddr_min_;
                for (uint16_t i = 0; i < header->e_phnum; ++i) {
                    const auto &entry = phdr[i];
                    if (entry.p_type != PT_LOAD) continue;
                    if (entry.p_vaddr > UINTPTR_MAX - bias ||
                        entry.p_memsz > SIZE_MAX ||
                        entry.p_memsz > UINTPTR_MAX - (bias + entry.p_vaddr))
                        return false;
                    load_ranges_.emplace_back(
                            bias + static_cast<uintptr_t>(entry.p_vaddr),
                            static_cast<size_t>(entry.p_memsz));
                }
            }
        }
        valid_ = true;
        return true;
    }
    bool Elf::LoadSymbols() {
        if (!valid_) return false;
        if (for_dynamic_) return LoadSymbolsForDynamic();
        else return LoadSymbolsForFull();
    }
    
    bool Elf::LoadSymbolsForDynamic() {
        if (dynamic_off_ == 0 || dynamic_size_ < sizeof(ElfW(Dyn)) ||
            dynamic_size_ % sizeof(ElfW(Dyn)) != 0 ||
            load_base_ < vaddr_min_) return false;
        const uintptr_t bias = load_base_ - vaddr_min_;
        if (dynamic_off_ > UINTPTR_MAX - bias) return false;
        const uintptr_t dynamic_address = bias + dynamic_off_;
        if (!ContainsRuntimeRange(dynamic_address, dynamic_size_)) {
            LOGE("PT_DYNAMIC exceeds mapped PT_LOAD ranges");
            return false;
        }

        uintptr_t hash_address = 0;
        uintptr_t gnu_hash_address = 0;
        uintptr_t strtab_address = 0;
        uintptr_t symtab_address = 0;
        bool found_null = false;
        bool found_syment = false;
        for (size_t i = 0; i < dynamic_size_ / sizeof(ElfW(Dyn)); ++i) {
            const auto &entry = reinterpret_cast<const ElfW(Dyn) *>(dynamic_address)[i];
            if (entry.d_tag == DT_NULL) {
                found_null = true;
                break;
            }
            auto pointerFromVaddr = [&](ElfW(Addr) value, uintptr_t *out) {
                const uintptr_t raw = static_cast<uintptr_t>(value);
                // Some dynamic linkers relocate d_ptr entries in-place while
                // others leave ELF virtual addresses. Accept only a candidate
                // that is actually inside one of this image's PT_LOAD ranges.
                if (RuntimeRemaining(raw) != 0) {
                    *out = raw;
                    return true;
                }
                if (raw > UINTPTR_MAX - bias) return false;
                const uintptr_t relocated = bias + raw;
                if (RuntimeRemaining(relocated) == 0) return false;
                *out = relocated;
                return true;
            };
            switch (entry.d_tag) {
                case DT_STRTAB:
                    if (!pointerFromVaddr(entry.d_un.d_ptr, &strtab_address)) return false;
                    break;
                case DT_STRSZ:
                    dynstr_size_ = static_cast<size_t>(entry.d_un.d_val);
                    break;
                case DT_SYMTAB:
                    if (!pointerFromVaddr(entry.d_un.d_ptr, &symtab_address)) return false;
                    break;
                case DT_SYMENT:
                    found_syment = entry.d_un.d_val == sizeof(ElfW(Sym));
                    break;
                case DT_PLTREL:
                    if (entry.d_un.d_val != DT_REL && entry.d_un.d_val != DT_RELA)
                        return false;
                    is_use_rela_ = entry.d_un.d_val == DT_RELA;
                    has_plt_reloc_format_ = true;
                    break;
                case DT_JMPREL:
                    if (!pointerFromVaddr(entry.d_un.d_ptr,
                                          reinterpret_cast<uintptr_t *>(&rel_plt_))) return false;
                    break;
                case DT_PLTRELSZ:
                    rel_plt_size_ = entry.d_un.d_val;
                    break;
                case DT_REL:
                    if (!pointerFromVaddr(entry.d_un.d_ptr,
                                          reinterpret_cast<uintptr_t *>(&rel_dyn_))) return false;
                    rel_dyn_is_rela_ = false;
                    break;
                case DT_RELA:
                    if (!pointerFromVaddr(entry.d_un.d_ptr,
                                          reinterpret_cast<uintptr_t *>(&rel_dyn_))) return false;
                    rel_dyn_is_rela_ = true;
                    break;
                case DT_RELENT:
                    if (entry.d_un.d_val != sizeof(ElfW(Rel))) return false;
                    break;
                case DT_RELAENT:
                    if (entry.d_un.d_val != sizeof(ElfW(Rela))) return false;
                    break;
                case DT_RELSZ:
                case DT_RELASZ:
                    rel_dyn_size_ = entry.d_un.d_val;
                    break;
                case DT_HASH:
                    if (!pointerFromVaddr(entry.d_un.d_ptr, &hash_address)) return false;
                    break;
                case DT_GNU_HASH:
                    if (!pointerFromVaddr(entry.d_un.d_ptr, &gnu_hash_address)) return false;
                    break;
                default:
                    // Android packed relocations are not ELF Rel/ Rela arrays;
                    // deliberately do not pass APS2 data to the regular walker.
                    break;
            }
        }
        if (!found_null || !strtab_address || !symtab_address ||
            dynstr_size_ == 0 || !found_syment ||
            !ContainsRuntimeRange(strtab_address, dynstr_size_) ||
            strtab_address % alignof(char) != 0 ||
            symtab_address % alignof(ElfW(Sym)) != 0) {
            LOGE("incomplete or out-of-range dynamic symbol metadata");
            return false;
        }
        dynstr_ = reinterpret_cast<const char *>(strtab_address);
        dynsym_ = reinterpret_cast<ElfW(Sym) *>(symtab_address);

        if (hash_address) {
            if (hash_address % alignof(ElfW(Word)) != 0 ||
                !ContainsRuntimeRange(hash_address, 2 * sizeof(ElfW(Word)))) return false;
            auto *raw = reinterpret_cast<ElfW(Word) *>(hash_address);
            const uint64_t words = 2ULL + raw[0] + raw[1];
            if (words > SIZE_MAX / sizeof(ElfW(Word)) ||
                !ContainsRuntimeRange(hash_address,
                                      static_cast<size_t>(words * sizeof(ElfW(Word)))) ||
                !validateSysvHash(raw, static_cast<size_t>(
                        words > SIZE_MAX ? 0 : words))) {
                LOGE("invalid or out-of-range DT_HASH table");
                return false;
            }
            nbucket_ = raw[0];
            dynsym_count_ = raw[1];
            bucket_ = raw + 2;
            chain_ = bucket_ + nbucket_;
        }

        if (gnu_hash_address) {
            if (gnu_hash_address % alignof(ElfW(Word)) != 0 ||
                !ContainsRuntimeRange(gnu_hash_address, 4 * sizeof(ElfW(Word)))) return false;
            auto *raw = reinterpret_cast<ElfW(Word) *>(gnu_hash_address);
            gnu_nbucket_ = raw[0];
            gnu_symndx_ = raw[1];
            gnu_bloom_size_ = raw[2];
            gnu_shift2_ = raw[3];
            if (gnu_nbucket_ == 0 || gnu_bloom_size_ == 0 ||
                gnu_shift2_ >= sizeof(uint32_t) * 8) return false;
            const uint64_t bloom_bytes =
                    static_cast<uint64_t>(gnu_bloom_size_) * sizeof(ElfW(Addr));
            const uint64_t bucket_bytes =
                    static_cast<uint64_t>(gnu_nbucket_) * sizeof(uint32_t);
            const uint64_t prefix_bytes = 4ULL * sizeof(ElfW(Word)) +
                                          bloom_bytes + bucket_bytes;
            if (prefix_bytes > SIZE_MAX ||
                !ContainsRuntimeRange(gnu_hash_address,
                                      static_cast<size_t>(prefix_bytes))) return false;
            gnu_bloom_filter_ = reinterpret_cast<uintptr_t *>(raw + 4);
            gnu_bucket_ = reinterpret_cast<uint32_t *>(
                    reinterpret_cast<uint8_t *>(gnu_bloom_filter_) + bloom_bytes);
            gnu_chain_ = gnu_bucket_ + gnu_nbucket_;
            gnu_chain_count_ = RuntimeRemaining(
                    reinterpret_cast<uintptr_t>(gnu_chain_)) / sizeof(uint32_t);
            const size_t previous_symbol_count = dynsym_count_;
            if (!ValidateGnuHash(gnu_bucket_, gnu_nbucket_, gnu_chain_,
                                 gnu_chain_count_) ||
                (previous_symbol_count != 0 && dynsym_count_ > previous_symbol_count)) {
                LOGE("invalid or out-of-range DT_GNU_HASH chain");
                return false;
            }
        }
        if (dynsym_count_ == 0 ||
            dynsym_count_ > SIZE_MAX / sizeof(ElfW(Sym)) ||
            !ContainsRuntimeRange(symtab_address,
                                  dynsym_count_ * sizeof(ElfW(Sym)))) {
            LOGE("dynamic symbol table exceeds mapped range");
            return false;
        }

        if (rel_plt_ != 0 || rel_plt_size_ != 0) {
            const size_t entry_size = is_use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
            if (!has_plt_reloc_format_ || rel_plt_ == 0 || rel_plt_size_ == 0 ||
                rel_plt_size_ % entry_size != 0 ||
                !ContainsRuntimeRange(rel_plt_, rel_plt_size_)) {
                LOGE("invalid DT_JMPREL range");
                return false;
            }
        }
        if ((rel_dyn_ != 0 || rel_dyn_size_ != 0) &&
            (rel_dyn_ == 0 || rel_dyn_size_ == 0 ||
             rel_dyn_size_ % (rel_dyn_is_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel))) != 0 ||
             !ContainsRuntimeRange(rel_dyn_, rel_dyn_size_))) {
            LOGE("invalid dynamic relocation range");
            return false;
        }
        return nbucket_ != 0 || gnu_nbucket_ != 0;
    }

    bool Elf::LoadSymbolsForFull() {
        if (header_->e_shnum == 0 || header_->e_shstrndx == SHN_UNDEF ||
            header_->e_shstrndx >= header_->e_shnum ||
            header_->e_shentsize != sizeof(ElfW(Shdr)) ||
            !rangeWithin(parse_size_, header_->e_shoff,
                         static_cast<uint64_t>(header_->e_shnum) * sizeof(ElfW(Shdr)))) {
            LOGE("invalid ELF section table metadata");
            return false;
        }

        auto *section_header = offsetOf<ElfW(Shdr) *>(header_, header_->e_shoff);
        const auto &names_header = section_header[header_->e_shstrndx];
        if (names_header.sh_type != SHT_STRTAB ||
            !rangeWithin(parse_size_, names_header.sh_offset, names_header.sh_size)) {
            LOGE("invalid ELF section-name string table");
            return false;
        }
        const char *section_str =
                offsetOf<const char *>(header_, names_header.sh_offset);

        for (uint16_t i = 0; i < header_->e_shnum; ++i) {
            const auto *section = &section_header[i];
            if (section->sh_type != SHT_NOBITS &&
                !rangeWithin(parse_size_, section->sh_offset, section->sh_size)) {
                LOGE("ELF section %u exceeds input bounds", i);
                return false;
            }
            if (section->sh_name >= names_header.sh_size) return false;
            const char *name = section_str + section->sh_name;
            const size_t name_remaining = names_header.sh_size - section->sh_name;
            const auto *name_end = static_cast<const char *>(
                    memchr(name, '\0', name_remaining));
            if (!name_end) return false;
            const std::string_view sname{name,
                    static_cast<size_t>(name_end - name)};
            switch (section->sh_type) {
                case SHT_DYNSYM: {
                    if (section->sh_entsize != sizeof(ElfW(Sym)) ||
                        section->sh_size % sizeof(ElfW(Sym)) != 0 ||
                        section->sh_link >= header_->e_shnum ||
                        section_header[section->sh_link].sh_type != SHT_STRTAB) {
                        LOGE("invalid ELF dynamic symbol table");
                        return false;
                    }
                    dynsym_ = offsetOf<ElfW(Sym) *>(header_, section->sh_offset);
                    dynsym_count_ = section->sh_size / sizeof(ElfW(Sym));
                    const auto &str = section_header[section->sh_link];
                    dynstr_ = offsetOf<const char *>(header_, str.sh_offset);
                    dynstr_size_ = str.sh_size;
                    break;
                }
                case SHT_SYMTAB: {
                    if (sname == ".symtab"sv) {
                        if (section->sh_entsize != sizeof(ElfW(Sym)) ||
                            section->sh_size % sizeof(ElfW(Sym)) != 0 ||
                            section->sh_link >= header_->e_shnum ||
                            section_header[section->sh_link].sh_type != SHT_STRTAB) {
                            LOGE("invalid ELF symbol table");
                            return false;
                        }
                        symtab_count_ = section->sh_size / sizeof(ElfW(Sym));
                        symtab_ = offsetOf<ElfW(Sym) *>(header_, section->sh_offset);
                        symstr_ = section_header[section->sh_link].sh_offset;
                        symstr_size_ = section_header[section->sh_link].sh_size;
                    }
                    break;
                }
                case SHT_STRTAB:
                    if (sname == ".dynstr"sv) {
                        dynstr_ = offsetOf<const char *>(header_, section->sh_offset);
                        dynstr_size_ = section->sh_size;
                    } else if (sname == ".strtab"sv) {
                        symstr_ = section->sh_offset;
                        symstr_size_ = section->sh_size;
                    }
                    break;
                case SHT_PROGBITS:
                    if (sname == ".gnu_debugdata"sv) {
                        auto debug_data = unxz(
                                offsetOf<const uint8_t *>(header_, section->sh_offset),
                                section->sh_size);
                        if (!debug_data.empty()) {
                            auto elf = std::make_unique<Elf>();
                            if (elf->InitFromData(std::move(debug_data)) &&
                                elf->LoadSymbols()) {
                                elf->SetLoadBase(GetLoadBase());
                                elf->vaddr_min_ = vaddr_min_;
                                gnu_debugdata_elf_ = std::move(elf);
                            } else {
                                LOGE("failed to initialize GNU debugdata");
                            }
                        }
                    }
                    break;
                case SHT_HASH: {
                    if (section->sh_size < 2 * sizeof(ElfW(Word))) return false;
                    auto *raw = offsetOf<ElfW(Word) *>(header_, section->sh_offset);
                    const uint64_t words = 2ULL + raw[0] + raw[1];
                    if (words > SIZE_MAX / sizeof(ElfW(Word)) ||
                        words * sizeof(ElfW(Word)) > section->sh_size ||
                        !validateSysvHash(raw, static_cast<size_t>(words))) {
                        LOGE("invalid or truncated ELF SysV hash table");
                        return false;
                    }
                    nbucket_ = raw[0];
                    const size_t hash_symbol_count = raw[1];
                    if (dynsym_count_ != 0 && dynsym_count_ != hash_symbol_count)
                        return false;
                    dynsym_count_ = hash_symbol_count;
                    bucket_ = raw + 2;
                    chain_ = bucket_ + nbucket_;
                    break;
                }
                case SHT_GNU_HASH: {
                    if (section->sh_size < 4 * sizeof(ElfW(Word))) return false;
                    auto *raw = offsetOf<ElfW(Word) *>(header_, section->sh_offset);
                    gnu_nbucket_ = raw[0];
                    gnu_symndx_ = raw[1];
                    gnu_bloom_size_ = raw[2];
                    gnu_shift2_ = raw[3];
                    if (gnu_bloom_size_ == 0 || gnu_nbucket_ == 0 ||
                        gnu_shift2_ >= sizeof(uint32_t) * 8) return false;
                    const uint64_t bloom_bytes =
                            static_cast<uint64_t>(gnu_bloom_size_) * sizeof(ElfW(Addr));
                    const uint64_t bucket_bytes =
                            static_cast<uint64_t>(gnu_nbucket_) * sizeof(uint32_t);
                    const uint64_t prefix_bytes = 4ULL * sizeof(ElfW(Word)) +
                                                  bloom_bytes + bucket_bytes;
                    if (prefix_bytes > section->sh_size) return false;
                    gnu_bloom_filter_ = reinterpret_cast<uintptr_t *>(raw + 4);
                    gnu_bucket_ = reinterpret_cast<uint32_t *>(
                            reinterpret_cast<uint8_t *>(gnu_bloom_filter_) + bloom_bytes);
                    gnu_chain_ = gnu_bucket_ + gnu_nbucket_;
                    const size_t chain_words =
                            (section->sh_size - static_cast<size_t>(prefix_bytes)) /
                            sizeof(uint32_t);
                    const size_t previous_count = dynsym_count_;
                    if (!ValidateGnuHash(gnu_bucket_, gnu_nbucket_, gnu_chain_,
                                         chain_words) ||
                        (previous_count != 0 && dynsym_count_ > previous_count)) {
                        LOGE("invalid ELF GNU hash chain");
                        return false;
                    }
                    break;
                }
                default:
                    break;
            }
        }
        if (dynsym_ && (dynsym_count_ == 0 ||
            dynsym_count_ > SIZE_MAX / sizeof(ElfW(Sym)) ||
            !rangeWithin(parse_size_,
                         reinterpret_cast<uintptr_t>(dynsym_) - parse_base_,
                         dynsym_count_ * sizeof(ElfW(Sym))))) return false;
        if (dynstr_ && !rangeWithin(parse_size_,
                reinterpret_cast<uintptr_t>(dynstr_) - parse_base_, dynstr_size_))
            return false;
        return true;
    }

    ElfW(Sym)* Elf::ElfLookup(std::string_view name, uint32_t hash) const {
        if (auto idx = ElfLookupIdx(name, hash); idx != 0) return dynsym_ + idx;
        return nullptr;
    }

    uint32_t Elf::ElfLookupIdx(std::string_view name, uint32_t hash) const {
        if (!dynsym_ || !dynstr_ || !bucket_ || !chain_ ||
            nbucket_ == 0 || dynsym_count_ == 0) return 0;
        uint32_t index = bucket_[hash % nbucket_];
        for (size_t steps = 0; index != 0 && steps < dynsym_count_; ++steps) {
            if (index >= dynsym_count_) return 0;
            const auto &symbol = dynsym_[index];
            if (symbol.st_name < dynstr_size_) {
                const char *symbol_name = dynstr_ + symbol.st_name;
                const size_t remaining = dynstr_size_ - symbol.st_name;
                const auto *end = static_cast<const char *>(
                        memchr(symbol_name, '\0', remaining));
                if (end && std::string_view(symbol_name,
                        static_cast<size_t>(end - symbol_name)) == name) return index;
            }
            index = chain_[index];
        }
        return 0;
    }

    ElfW(Sym)* Elf::GnuLookup(std::string_view name, uint32_t hash) const {
        if (auto idx = GnuLookupIdx(name, hash); idx != 0) return dynsym_ + idx;
        return nullptr;
    }

    uint32_t Elf::GnuLookupIdx(std::string_view name, uint32_t hash) const {
        static constexpr auto bloom_mask_bits = sizeof(ElfW(Addr)) * 8;
        if (!dynsym_ || !dynstr_ || !gnu_bloom_filter_ || !gnu_bucket_ ||
            !gnu_chain_ || gnu_nbucket_ == 0 || gnu_bloom_size_ == 0 ||
            gnu_chain_count_ == 0 || gnu_shift2_ >= 32) return 0;

        const auto bloom_word =
                gnu_bloom_filter_[(hash / bloom_mask_bits) % gnu_bloom_size_];
        const uintptr_t mask = (uintptr_t{1} << (hash % bloom_mask_bits)) |
                (uintptr_t{1} << ((hash >> gnu_shift2_) % bloom_mask_bits));
        if ((mask & bloom_word) != mask) return 0;

        uint32_t index = gnu_bucket_[hash % gnu_nbucket_];
        if (index == 0 || index < gnu_symndx_ || index >= dynsym_count_) return 0;
        for (size_t steps = 0; steps < gnu_chain_count_; ++steps, ++index) {
            if (index >= dynsym_count_) return 0;
            const size_t chain_index = static_cast<size_t>(index - gnu_symndx_);
            if (chain_index >= gnu_chain_count_) return 0;
            const uint32_t chain_hash = gnu_chain_[chain_index];
            const auto &symbol = dynsym_[index];
            if (((chain_hash ^ hash) >> 1) == 0 && symbol.st_name < dynstr_size_) {
                const char *symbol_name = dynstr_ + symbol.st_name;
                const size_t remaining = dynstr_size_ - symbol.st_name;
                const auto *end = static_cast<const char *>(
                        memchr(symbol_name, '\0', remaining));
                if (end && std::string_view(symbol_name,
                        static_cast<size_t>(end - symbol_name)) == name) return index;
            }
            if (chain_hash & 1U) break;
        }
        return 0;
    }

    void Elf::MayInitLinearMap() const {
        if (for_dynamic_) return;
        if (symtabs_.empty()) {
            if (symtab_ != nullptr && symstr_ != 0) {
                for (ElfW(Off) i = 0; i < symtab_count_; i++) {
                    unsigned int st_type = ELF_ST_TYPE(symtab_[i].st_info);
                    if (symtab_[i].st_name >= symstr_size_) continue;
                    const char *st_name = offsetOf<const char *>(
                            header_, symstr_ + symtab_[i].st_name);
                    const size_t remaining = symstr_size_ - symtab_[i].st_name;
                    if (!memchr(st_name, '\0', remaining)) continue;
                    if ((st_type == STT_FUNC || st_type == STT_OBJECT) &&
                        symtab_[i].st_size) {
                        symtabs_.emplace(st_name, &symtab_[i]);
                    }
                }
            }
        }
    }

    ElfW(Sym)* Elf::LinearLookup(std::string_view name) const {
        MayInitLinearMap();
        if (auto i = symtabs_.find(name); i != symtabs_.end()) {
            return i->second;
        } else {
            return nullptr;
        }
    }

    std::vector<ElfW(Addr)> Elf::LinearRangeLookup(std::string_view name) const {
        MayInitLinearMap();
        std::vector<ElfW(Addr)> res;
        for (auto [i, end] = symtabs_.equal_range(name); i != end; ++i) {
            auto offset = i->second->st_value;
            res.emplace_back(offset);
        }
        if (gnu_debugdata_) {
            auto gnu_debugdata = gnu_debugdata_elf_->LinearRangeLookup(name);
            res.insert(res.end(), gnu_debugdata.begin(), gnu_debugdata.end());
        }
        return res;
    }

    ElfW(Sym)* Elf::PrefixLookupFirstSym(std::string_view prefix) const {
        MayInitLinearMap();
        if (auto i = symtabs_.lower_bound(prefix);
                i != symtabs_.end() && i->first.starts_with(prefix)) {
            return i->second;
        } else if (gnu_debugdata_elf_) {
            return gnu_debugdata_elf_->PrefixLookupFirstSym(prefix);
        } else {
            return 0;
        }
    }

    ElfW(Addr) Elf::PrefixLookupFirst(std::string_view prefix) const {
        MayInitLinearMap();
        if (auto sym = PrefixLookupFirstSym(prefix); sym != nullptr) {
            return sym->st_value;
        }
        return 0;
    }

    ElfW(Sym)* Elf::getSym(std::string_view name, uint32_t gnu_hash,
                                  uint32_t elf_hash) const {
        auto sym = GnuLookup(name, gnu_hash);
        if (!sym) sym = ElfLookup(name, elf_hash);
        if (!sym && gnu_debugdata_elf_) sym = gnu_debugdata_elf_->getSym(name, gnu_hash, elf_hash);
        if (!sym) sym = LinearLookup(name);
        return sym;
    }

    bool Elf::InitFromData(std::vector<uint8_t> &&gnu_debugdata) {
        const size_t data_size = gnu_debugdata.size();
        if (data_size < sizeof(ElfW(Ehdr))) return false;
        auto data = reinterpret_cast<uintptr_t>(gnu_debugdata.data());
        if (!Init(data, data, data_size)) return false;
        gnu_debugdata_ =
                std::make_unique<std::vector<uint8_t>>(std::move(gnu_debugdata));
        return true;
    }

    bool Elf::InitFromFile(std::string_view so_path, uintptr_t base_addr, bool init_sym, size_t file_off) {
        auto [addr, size] = OpenLibrary(so_path, file_off);
        path = so_path;
        owns_mapping_ = addr != 0 && size != 0;
        if (Elf::Init(base_addr, addr, size)) {
            return !init_sym || LoadSymbols();
        }
        return false;
    }

    bool Elf::InitFromMemory(void *addr, bool init_sym, size_t size) {
        auto a = reinterpret_cast<uintptr_t>(addr);
        for_dynamic_ = true;
        if (Elf::Init(a, a, size)) {
            return !init_sym || LoadSymbols();
        }
        for_dynamic_ = false;
        return false;
    }

    Elf::~Elf() {
        if (owns_mapping_ && parse_size_ != 0)
            munmap(reinterpret_cast<void *>(parse_base_), parse_size_);
    }

    uint32_t Elf::LinearLookupForDyn(std::string_view name) const {
        if (!for_dynamic_) return 0;
        if (!dynsym_ || !dynstr_ || !gnu_symndx_) return 0;
        for (uint32_t idx = 0; idx < gnu_symndx_ && idx < dynsym_count_; idx++) {
            const auto &sym = dynsym_[idx];
            if (sym.st_name >= dynstr_size_) continue;
            const char *symbol_name = dynstr_ + sym.st_name;
            const size_t remaining = dynstr_size_ - sym.st_name;
            const auto *end = static_cast<const char *>(memchr(symbol_name, '\0', remaining));
            if (end && std::string_view(symbol_name,
                    static_cast<size_t>(end - symbol_name)) == name) return idx;
        }
        return 0;
    }

    ElfW(Sym)* Elf::getSym(std::string_view name) const {
        return getSym(name, GnuHash(name), ElfHash(name));
    }

    ElfW(Sym)* Elf::getSymByPrefix(std::string_view name) const {
        return PrefixLookupFirstSym(name);
    }

    std::vector<uintptr_t> Elf::FindPltAddr(std::string_view name) const {
        std::vector<uintptr_t> res;

        uint32_t idx = GnuLookupIdx(name, GnuHash(name));
        if (!idx) idx = ElfLookupIdx(name, ElfHash(name));
        if (!idx) idx = LinearLookupForDyn(name);
        if (!idx) return res;
        const uintptr_t bias = load_base_ - vaddr_min_;

        auto looper = [&res, idx, bias, this]<typename T>(auto begin, auto size, bool is_plt) -> void {
            if (size == 0 || size % sizeof(T) != 0 ||
                begin > UINTPTR_MAX - size ||
                !ContainsRuntimeRange(begin, size)) return;
            const auto *rel_begin = reinterpret_cast<const T *>(begin);
            const size_t count = size / sizeof(T);
            for (size_t i = 0; i < count; ++i) {
                const auto *rel = rel_begin + i;
                auto r_info = rel->r_info;
                auto r_offset = rel->r_offset;
                auto r_sym = ELF_R_SYM(r_info);
                auto r_type = ELF_R_TYPE(r_info);
                if (r_sym != idx || r_sym >= dynsym_count_) continue;
                if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
                if (!is_plt && r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT) {
                    continue;
                }
                if (r_offset > UINTPTR_MAX - bias) continue;
                const uintptr_t addr = bias + r_offset;
                if (addr > bias && addr % alignof(void*) == 0 &&
                    ContainsRuntimeRange(addr, sizeof(void*))) {
                    res.emplace_back(addr);
                }
            }
        };

        if (rel_plt_ && rel_plt_size_) {
            if (is_use_rela_)
                looper.template operator()<ElfW(Rela)>(rel_plt_, rel_plt_size_, true);
            else
                looper.template operator()<ElfW(Rel)>(rel_plt_, rel_plt_size_, true);
        }
        if (rel_dyn_ && rel_dyn_size_) {
            if (rel_dyn_is_rela_)
                looper.template operator()<ElfW(Rela)>(rel_dyn_, rel_dyn_size_, false);
            else
                looper.template operator()<ElfW(Rel)>(rel_dyn_, rel_dyn_size_, false);
        }

        return res;
    }

    void Elf::forEachSymbols(std::function<bool(const char*, ElfW(Sym)* sym)> &&fn) const {
        for (auto &[name, sym]: symtabs_) {
            if (!fn(name.data(), sym)) break;
        }
        if (gnu_debugdata_elf_) gnu_debugdata_elf_->forEachSymbols(std::move(fn));
    }
} // namespace elf_parser
