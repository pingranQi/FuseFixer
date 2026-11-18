#include <string>
#include <string_view>
#include <algorithm>
#include <atomic>
#include <map>
#include <vector>
#include <cstdint>
#include <cerrno>


#include <link.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

#include "lsp_api.h"
#include "elf_parser.hpp"
#include "maps_scan.hpp"
#include "logging.h"
#include "utf8_utils.hpp"

#include "fuse.h"
#include <jni.h>

// https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/upstream-openbsd/lib/libc/string/strcasecmp.c;l=35-88;drc=b364683ea65e24070c77f1673a8c155665eb894e

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
std::string escape_string(std::string_view sv) {
    std::string os;
    char buf[8];
    for (char i : sv) {
        if (i >= 32 && i < 127) [[likely]] {
            os += i;
        } else {
            snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char) i);
            os += buf;
        }
    }
    return os;
}

static HookFunType hook_func = nullptr;
static UnhookFunType unhook_func = nullptr;

static bool install_inline_hook(void* target, void* replacement, void** original,
                               const char* name) {
    if (!target) {
        LOGW("skip %s hook: target symbol not found", name);
        return false;
    }
    if (!hook_func) {
        LOGE("skip %s hook: hook function is unavailable", name);
        return false;
    }
    const int result = hook_func(target, replacement, original);
    if (result != 0) {
        LOGE("hook %s failed: result=%d", name, result);
        return false;
    }
    if (!original || !*original) {
        LOGE("hook %s returned success without a trampoline; attempting rollback", name);
        if (unhook_func && unhook_func(target) != 0) {
            LOGE("hook %s rollback failed", name);
        }
        return false;
    }
    LOGI("hook %s installed", name);
    return true;
}

bool (*old_is_package_owned_path)(const std::string& path, const std::string& fuse_path);
bool my_is_package_owned_path(const std::string& path, const std::string& fuse_path) {
    if (has_default_ignorable_code_point(path)) [[unlikely]] {
        std::string new_path{path};
        remove_default_ignorable_code_point(new_path);
        if (!old_is_package_owned_path) return false;
        auto r = old_is_package_owned_path(new_path, fuse_path);
        LOGD("fix is_package_owned_path: %s res=%d", escape_string(path).c_str(), r);
        return r;
    }
    return old_is_package_owned_path ? old_is_package_owned_path(path, fuse_path) : false;
}

bool (*old_is_app_accessible_path)(struct fuse* fuse, const std::string& path, uid_t uid);
bool my_is_app_accessible_path(struct fuse* fuse, const std::string& path, uid_t uid) {
    if (has_default_ignorable_code_point(path)) [[unlikely]] {
        std::string new_path{path};
        remove_default_ignorable_code_point(new_path);
        if (!old_is_app_accessible_path) return false;
        auto r = old_is_app_accessible_path(fuse, new_path, uid);
        LOGD("fix is_app_accessible_path: %s uid=%d res=%d", escape_string(path).c_str(), uid, r);
        return r;
    }
    return old_is_app_accessible_path ? old_is_app_accessible_path(fuse, path, uid) : false;
}

// Magic is here?
// https://cs.android.com/android/platform/superproject/main/+/main:packages/providers/MediaProvider/jni/FuseDaemon.cpp;l=699-701;drc=61197364367c9e404c7da6900658f1b16c42d0da
bool (*old_is_bpf_backing_path)(const std::string& path);
bool my_is_bpf_backing_path(const std::string& path) {
    bool res;
    if (has_default_ignorable_code_point(path)) [[unlikely]] {
        std::string new_path{path};
        remove_default_ignorable_code_point(new_path);
        if (!old_is_bpf_backing_path) return false;
        res = old_is_bpf_backing_path(new_path);
        LOGD("fix is_bpf_backing_path: %s res=%d", escape_string(path).c_str(), res);
    } else {
        res = old_is_bpf_backing_path ? old_is_bpf_backing_path(path) : false;
    }
    return res;
}

// hook strcasecmp to solve mount point passthrough
// https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/providers/MediaProvider/jni/node-inl.h;l=529-555;drc=b415bef4d9bdd8f506e89577dafdb9cda12bcd69
// only NodeCompare uses strcasecmp
int (*old_strcasecmp)(const char *s1, const char *s2);
int my_strcasecmp(const char *s1, const char *s2) {
    return strcasecmp_fix(s1, s2);
}

// https://cs.android.com/android/platform/superproject/main/+/main:packages/providers/MediaProvider/jni/FuseUtils.cpp;l=50-52;drc=61197364367c9e404c7da6900658f1b16c42d0da
// Fix containsMount
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/strings.cpp;l=119;drc=61197364367c9e404c7da6900658f1b16c42d0da
bool (*old_EqualsIgnoreCase)(std::string_view lhs, std::string_view rhs);
bool my_EqualsIgnoreCase(std::string_view lhs, std::string_view rhs) {
    return svcasecmp_fix(lhs, rhs) == 0;
}

int (*old_fuse_lowlevel_notify_inval_entry)(void *se, uint64_t parent,
                                     const char *name, size_t namelen);
int my_fuse_lowlevel_notify_inval_entry(void *se, uint64_t parent,
                                     const char *name, size_t namelen) {
    if (!old_fuse_lowlevel_notify_inval_entry) return -1;
    auto ret = old_fuse_lowlevel_notify_inval_entry(se, parent, name, namelen);
    const auto safe_name = name
            ? escape_string(std::string_view{name, namelen})
            : std::string{"<null>"};
    LOGI("notify_inval_entry: ino=0x%lx name=%s ret=%d",
         (unsigned long) parent, safe_name.c_str(), ret);
    return ret;
}

std::string inodePath(uint64_t ino);

int (*old_fuse_lowlevel_notify_inval_inode)(void *se, uint64_t ino,
                                     off_t off, off_t len);
int my_fuse_lowlevel_notify_inval_inode(void *se, uint64_t ino,
                                     off_t off, off_t len) {
    if (!old_fuse_lowlevel_notify_inval_inode) return -1;
    auto ret = old_fuse_lowlevel_notify_inval_inode(se, ino, off, len);
    LOGI("notify_inval_inode: ino=0x%lx name=%s ret=%d",
         (unsigned long) ino, escape_string(inodePath(ino)).c_str(), ret);
    return ret;
}


std::string (*node_BuildPath_ptr)(void* node);

std::string inodePath(uint64_t ino) {
    if (ino == 1) [[unlikely]] {
        return "(ROOT)";
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "(%p)", (void*) ino);
    if (node_BuildPath_ptr) [[likely]] {
        return buf + node_BuildPath_ptr(reinterpret_cast<void*>(ino));
    } else {
        return buf;
    }
}

void (*old_pf_lookup)(fuse_req_t req, uint64_t parent, const char* name);
void my_pf_lookup(fuse_req_t req, uint64_t parent, const char* name) {
    LOGI("lookup: req=%lu parent=%s name=%s", (unsigned long) req->unique, escape_string(inodePath(parent)).c_str(), escape_string(name).c_str());
    if (old_pf_lookup) old_pf_lookup(req, parent, name);
}

int (*old_fuse_reply_entry)(fuse_req_t req, const struct fuse_entry_param* e);
int my_fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param* e) {
    if (!old_fuse_reply_entry) return -1;
    if (!req || !e) return -EINVAL;
    auto ret = old_fuse_reply_entry(req, e);
    LOGI("fuse_reply_entry: req=%lu ino=%s timeout=%.2le attr_timeout=%.2le bpf_fd=%lu bpf_action=%lu backing_action=%lu backing_fd=%lu ret=%d", (unsigned long) req->unique,
         escape_string(inodePath(e->ino)).c_str(), e->entry_timeout, e->attr_timeout, (unsigned long) e->bpf_fd, (unsigned long) e->bpf_action, (unsigned long) e->backing_action, (unsigned long) e->backing_fd, ret);
    return ret;
}

static thread_local bool in_pf_lookup_postfilter = false;

int (*old_fuse_reply_err)(fuse_req_t req, int err);
int my_fuse_reply_err(fuse_req_t req, int err) {
    if (in_pf_lookup_postfilter) {
        LOGI("pf_lookup_postfilter fuse_reply_err req=%p %d", req, err);
    }
    return old_fuse_reply_err ? old_fuse_reply_err(req, err) : -1;
}

int (*old_fuse_reply_buf)(fuse_req_t req, const char *buf, size_t size);
int my_fuse_reply_buf(fuse_req_t req, const char *buf, size_t size) {
    if (in_pf_lookup_postfilter) {
        LOGI("pf_lookup_postfilter fuse_reply_buf req=%p", req);
    }
    return old_fuse_reply_buf ? old_fuse_reply_buf(req, buf, size) : -1;
}


static void (*old_pf_lookup_postfilter)(fuse_req_t req, fuse_ino_t parent, uint32_t error_in,
                                    const char* name, struct fuse_entry_out* feo,
                                    struct fuse_entry_bpf_out* febo);

static void my_pf_lookup_postfilter(fuse_req_t req, fuse_ino_t parent, uint32_t error_in,
                                 const char* name, struct fuse_entry_out* feo,
                                 struct fuse_entry_bpf_out* febo) {
    LOGI("pf_lookup_postfilter req=%p parent=%s name=%s", req,
         escape_string(inodePath(parent)).c_str(),
         escape_string(name ? std::string_view{name} : std::string_view{"<null>"}).c_str());
    const bool was_in_postfilter = in_pf_lookup_postfilter;
    in_pf_lookup_postfilter = true;
    if (old_pf_lookup_postfilter) old_pf_lookup_postfilter(req, parent, error_in, name, feo, febo);
    in_pf_lookup_postfilter = was_in_postfilter;
}

#ifdef NDEBUG
static constexpr bool kDebugFuse = false;
#else
static constexpr bool kDebugFuse = true;
#endif

void on_library_loaded(const char *name, void *handle) {
    static constexpr char kLibFuseJni[] = "libfuse_jni.so";
    LOGD("loaded: %s", name);
    if (std::string(name).ends_with(kLibFuseJni)) {
        LOGI("hooking libfuse_jni");
        uintptr_t base_addr = 0;
        size_t load_sz = 0;
        auto callback = [&](dl_phdr_info& info) -> bool {
            if (!info.dlpi_name) return false;
            std::string_view name{info.dlpi_name};
            if (!name.ends_with(kLibFuseJni)) return false;
            if (!info.dlpi_phdr) return false;
            auto phdrs = info.dlpi_phdr;
            uintptr_t vaddr_min = UINTPTR_MAX, vaddr_end = 0;
            for (auto i = 0; i < info.dlpi_phnum; i++) {
                const auto &phdr = phdrs[i];
                if (phdr.p_type != PT_LOAD) continue;
                if (phdr.p_memsz > UINTPTR_MAX - phdr.p_vaddr) {
                    LOGE("invalid PT_LOAD range in %s", info.dlpi_name);
                    return false;
                }
                vaddr_min = std::min(vaddr_min, static_cast<uintptr_t>(phdr.p_vaddr));
                vaddr_end = std::max(vaddr_end,
                        static_cast<uintptr_t>(phdr.p_vaddr + phdr.p_memsz));
            }
            if (vaddr_min == UINTPTR_MAX || vaddr_end <= vaddr_min ||
                info.dlpi_addr > UINTPTR_MAX - vaddr_min) {
                LOGE("invalid load range in %s", info.dlpi_name);
                return false;
            }
            load_sz = vaddr_end - vaddr_min;
            base_addr = info.dlpi_addr + vaddr_min;
            if (load_sz > UINTPTR_MAX - base_addr) {
                LOGE("load range overflow in %s", info.dlpi_name);
                load_sz = 0;
                base_addr = 0;
                return false;
            }
            return true;
        };
        using Callback = decltype(callback);
        dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) -> int {
            return reinterpret_cast<Callback*>(data)->operator()(*info) ? 1 : 0;
        }, &callback);

        LOGD("base %p load sz %zu", (void*) base_addr, load_sz);

        size_t off;
        std::string path{};

        uintptr_t exec_addr = 0, exec_sz = 0;
        int exec_perm = 0;
        struct ExecProtectionRestore {
            void* address = nullptr;
            size_t size = 0;
            int protection = 0;
            bool active = false;
            ~ExecProtectionRestore() {
                if (active && mprotect(address, size, protection) != 0) {
                    PLOGE("restore executable memory protection");
                }
            }
        } exec_protection_restore;

        maps_scan::MapInfo::ForEach([&](const maps_scan::MapInfo& info) -> bool {
            if (info.start == base_addr) {
                off = info.offset;
                path = info.path;
            }
            if (info.start < base_addr + load_sz && info.end > base_addr &&
                info.path == path && (info.perms & PROT_EXEC) != 0) {
                exec_addr = info.start;
                exec_perm = info.perms;
                exec_sz = info.end - info.start;
                // meet executable, we can return
                return false;
            }
            return true;
        });

        if (path.empty()) {
            LOGE("not found in maps");
            return;
        }

        LOGD("so path %s off %zu exec addr %p sz %zu", path.c_str(), off, (void*) exec_addr, exec_sz);

        // make executable area rwx to prevent their vma from splitting
        // this fixes unwind
        if (exec_addr) {
            if (mprotect((void*) exec_addr, exec_sz, exec_perm | PROT_WRITE) == 0) {
                exec_protection_restore.address = (void*) exec_addr;
                exec_protection_restore.size = exec_sz;
                exec_protection_restore.protection = exec_perm;
                exec_protection_restore.active = true;
            } else {
                PLOGE("fix memory perm");
            }
        }

        {
            elf_parser::Elf elf{};
            if (!elf.InitFromFile(path, base_addr, true, off)) {
                LOGE("init elf failed");
                return;
            }

            constexpr char is_app_accessible_path[] =
                "_ZN13mediaprovider4fuseL22is_app_accessible_pathEP4fuseRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEj";
            constexpr char is_app_accessible_path_alt[] =
                "_ZN13mediaprovider4fuseL22is_app_accessible_pathEP4fuseRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEj";
            constexpr char is_package_owned_path[] =
                "_ZL21is_package_owned_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_";
            constexpr char is_package_owned_path_alt[] =
                "_ZL21is_package_owned_pathRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_";
            constexpr char is_bpf_backing_path[] =
                "_ZL19is_bpf_backing_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE";
            constexpr char is_bpf_backing_path_alt[] =
                "_ZL19is_bpf_backing_pathRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE";

            if constexpr (kDebugFuse) {
                node_BuildPath_ptr = reinterpret_cast<decltype(node_BuildPath_ptr)>(elf.getSymbAddress(
                    "_ZNK13mediaprovider4fuse4node9BuildPathEv"));
                LOGI("BuildPath: %p", node_BuildPath_ptr);
            }

            auto p = elf.getSymbAddress(is_app_accessible_path);
            if (!p) p = elf.getSymbAddress(is_app_accessible_path_alt);
            LOGD("is_app_accessible_path: %p", p);

            install_inline_hook(p, (void*) my_is_app_accessible_path,
                                  (void**) &old_is_app_accessible_path, "is_app_accessible_path");

            p = elf.getSymbAddress(is_package_owned_path);
            if (!p) p = elf.getSymbAddress(is_package_owned_path_alt);
            LOGD("is_package_owned_path: %p", p);
            install_inline_hook(p, (void*) my_is_package_owned_path,
                                  (void**) &old_is_package_owned_path, "is_package_owned_path");

            p = elf.getSymbAddress(is_bpf_backing_path);
            if (!p) p = elf.getSymbAddress(is_bpf_backing_path_alt);
            LOGD("is_bpf_backing_path: %p", p);
            install_inline_hook(p, (void*) my_is_bpf_backing_path,
                                  (void**) &old_is_bpf_backing_path, "is_bpf_backing_path");

            if constexpr (kDebugFuse) {
                p = elf.getSymbAddress("_ZN13mediaprovider4fuseL9pf_lookupEP8fuse_reqmPKc");
                LOGI("pf_lookup: %p", p);
                install_inline_hook(p, (void*) my_pf_lookup,
                                      (void**) &old_pf_lookup, "pf_lookup");

                p = elf.getSymbAddress("_ZN13mediaprovider4fuseL20pf_lookup_postfilterEP8fuse_reqmjPKcP14fuse_entry_outP18fuse_entry_bpf_out");
                LOGI("pf_lookup_postfilter: %p", p);
                install_inline_hook(p, (void*) my_pf_lookup_postfilter,
                                      (void**) &old_pf_lookup_postfilter, "pf_lookup_postfilter");
            }
        }

        {
            elf_parser::Elf elf{};
            if (!elf.InitFromMemory((void*) base_addr, true, load_sz)) {
                LOGE("init elf for dyn failed");
                return;
            }

            auto pgsz = getpagesize();
            auto mask = pgsz - 1;

#define PAGE_START(x) ((char*) ((x) & ~mask))
#define PAGE_END(x) PAGE_START(x + mask)

            auto do_hook_plt = [&](const char* show_name, const char* sym,
                                   void* hook, void** old, const char* alt = nullptr) -> bool {
                auto addrs = elf.FindPltAddr(sym);
                if (addrs.empty() && alt) addrs = elf.FindPltAddr(alt);
                if (addrs.empty()) {
                    LOGW("no PLT relocations found for %s", show_name);
                    return false;
                }
                if (!old || !hook || pgsz <= 0 ||
                    (static_cast<size_t>(pgsz) & (static_cast<size_t>(pgsz) - 1)) != 0) {
                    LOGE("invalid PLT hook parameters for %s", show_name);
                    return false;
                }

                struct Patch {
                    uintptr_t slot;
                    void *original;
                    uintptr_t page;
                    int protection;
                };
                std::vector<Patch> patches;
                std::map<uintptr_t, int> pages;
                void *common_original = nullptr;
                bool saw_already_hooked = false;

                // Preflight every relocation before changing any page or slot.
                for (const uintptr_t slot : addrs) {
                    if (slot % alignof(void*) != 0 ||
                        slot > UINTPTR_MAX - sizeof(void*)) {
                        LOGE("unaligned/overflowing PLT slot for %s: %p",
                             show_name, reinterpret_cast<void*>(slot));
                        return false;
                    }
                    int protection = -1;
                    maps_scan::MapInfo::ForEach([&](const maps_scan::MapInfo& info) -> bool {
                        if (info.start <= slot &&
                            slot + sizeof(void*) <= info.end) {
                            protection = info.perms;
                            return false;
                        }
                        return true;
                    });
                    if (protection < 0 || (protection & PROT_READ) == 0) {
                        LOGE("cannot safely read PLT slot for %s at %p",
                             show_name, reinterpret_cast<void*>(slot));
                        return false;
                    }

                    auto &slot_ref = *reinterpret_cast<void **>(slot);
                    void *current = std::atomic_ref<void*>(slot_ref).load(
                            std::memory_order_acquire);
                    if (current == hook) {
                        saw_already_hooked = true;
                        continue;
                    }
                    if (!current) {
                        LOGE("null original PLT target for %s at %p",
                             show_name, reinterpret_cast<void*>(slot));
                        return false;
                    }
                    if (common_original && common_original != current) {
                        LOGE("PLT slots for %s resolve to different originals; refusing partial hook",
                             show_name);
                        return false;
                    }
                    common_original = current;
                    const uintptr_t page = slot &
                            ~(static_cast<uintptr_t>(pgsz) - 1);
                    patches.push_back({slot, current, page, protection});
                    auto [it, inserted] = pages.emplace(page, protection);
                    if (!inserted && it->second != protection) {
                        LOGE("inconsistent page protections for %s", show_name);
                        return false;
                    }
                }

                if (saw_already_hooked && !*old) {
                    LOGE("PLT slot for %s is already hooked but its original target is unknown",
                         show_name);
                    return false;
                }
                if (patches.empty()) {
                    if (saw_already_hooked && *old) return true;
                    LOGW("no unpatched PLT slots remain for %s", show_name);
                    return false;
                }
                if (saw_already_hooked && *old && *old != common_original) {
                    LOGE("existing PLT hook target changed for %s", show_name);
                    return false;
                }

                std::vector<uintptr_t> writable_pages;
                for (const auto &[page, protection] : pages) {
                    if (mprotect(reinterpret_cast<void*>(page), pgsz,
                                 protection | PROT_WRITE) != 0) {
                        PLOGE("make PLT page writable for %s", show_name);
                        for (auto it = writable_pages.rbegin();
                             it != writable_pages.rend(); ++it) {
                            const int original_protection = pages[*it];
                            if (mprotect(reinterpret_cast<void*>(*it), pgsz,
                                         original_protection) != 0)
                                PLOGE("rollback PLT page protection for %s", show_name);
                        }
                        return false;
                    }
                    writable_pages.push_back(page);
                }

                // Detect a concurrent loader/relocator update before writing.
                for (const auto &patch : patches) {
                    auto &slot_ref = *reinterpret_cast<void **>(patch.slot);
                    if (std::atomic_ref<void*>(slot_ref).load(std::memory_order_acquire)
                        != patch.original) {
                        LOGE("PLT slot changed during preflight for %s", show_name);
                        for (auto it = writable_pages.rbegin();
                             it != writable_pages.rend(); ++it) {
                            if (mprotect(reinterpret_cast<void*>(*it), pgsz,
                                         pages[*it]) != 0)
                                PLOGE("restore PLT page after preflight race");
                        }
                        return false;
                    }
                }

                for (const auto &patch : patches) {
                    auto &slot_ref = *reinterpret_cast<void **>(patch.slot);
                    std::atomic_ref<void*>(slot_ref).store(hook, std::memory_order_release);
                    __builtin___clear_cache(reinterpret_cast<char*>(patch.page),
                            reinterpret_cast<char*>(patch.page + pgsz));
                }

                bool protections_restored = true;
                for (auto it = writable_pages.rbegin(); it != writable_pages.rend(); ++it) {
                    if (mprotect(reinterpret_cast<void*>(*it), pgsz, pages[*it]) != 0) {
                        PLOGE("restore PLT page protection for %s", show_name);
                        protections_restored = false;
                    }
                }
                if (!protections_restored) {
                    // Best-effort transactional rollback: reopen every page,
                    // restore every original pointer, then restore protections.
                    bool rollback_writable = true;
                    for (const auto &[page, protection] : pages) {
                        if (mprotect(reinterpret_cast<void*>(page), pgsz,
                                     protection | PROT_WRITE) != 0) {
                            PLOGE("reopen PLT page for rollback (%s)", show_name);
                            rollback_writable = false;
                        }
                    }
                    if (rollback_writable) {
                        for (const auto &patch : patches) {
                            auto &slot_ref = *reinterpret_cast<void **>(patch.slot);
                            std::atomic_ref<void*>(slot_ref).store(
                                    patch.original, std::memory_order_release);
                            __builtin___clear_cache(reinterpret_cast<char*>(patch.page),
                                    reinterpret_cast<char*>(patch.page + pgsz));
                        }
                    } else {
                        LOGE("CRITICAL: unable to fully roll back PLT hook %s", show_name);
                    }
                    for (const auto &[page, protection] : pages) {
                        if (mprotect(reinterpret_cast<void*>(page), pgsz, protection) != 0)
                            PLOGE("restore PLT protection after rollback (%s)", show_name);
                    }
                    return false;
                }

                *old = common_original;
                LOGI("installed PLT hook %s in %zu slot(s)",
                     show_name, patches.size());
                return true;
            };

            do_hook_plt("strcasecmp", "strcasecmp", (void*) my_strcasecmp, (void**) &old_strcasecmp);
            do_hook_plt("EqualsIgnoreCase", "_ZN7android4base16EqualsIgnoreCaseENSt6__ndk117basic_string_viewIcNS1_11char_traitsIcEEEES5_",
                        (void*) my_EqualsIgnoreCase, (void**) &old_EqualsIgnoreCase, "_ZN7android4base16EqualsIgnoreCaseENSt3__117basic_string_viewIcNS1_11char_traitsIcEEEES5_");

            if constexpr (kDebugFuse) {
                do_hook_plt("fuse_lowlevel_notify_inval_entry", "fuse_lowlevel_notify_inval_entry",
                            (void *) my_fuse_lowlevel_notify_inval_entry,
                            (void **) &old_fuse_lowlevel_notify_inval_entry);
                do_hook_plt("fuse_lowlevel_notify_inval_inode", "fuse_lowlevel_notify_inval_inode",
                            (void *) my_fuse_lowlevel_notify_inval_inode,
                            (void **) &old_fuse_lowlevel_notify_inval_inode);
                do_hook_plt("fuse_reply_entry", "fuse_reply_entry",
                            (void *) my_fuse_reply_entry, (void **) &old_fuse_reply_entry);
                do_hook_plt("fuse_reply_buf", "fuse_reply_buf",
                            (void *) my_fuse_reply_buf, (void **) &old_fuse_reply_buf);
                do_hook_plt("fuse_reply_err", "fuse_reply_err",
                            (void *) my_fuse_reply_err, (void **) &old_fuse_reply_err);
            }
        }

    }
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    LOGI("Loaded");
    if (!entries || !entries->hook_func) {
        LOGE("native_init: missing hook API");
        hook_func = nullptr;
        unhook_func = nullptr;
        return nullptr;
    }
    hook_func = entries->hook_func;
    unhook_func = entries->unhook_func;
    return on_library_loaded;
}

static jint jstringToStandardUtf8(JNIEnv *env, jstring value, std::string *output) {
    if (!env || !value || !output) return EINVAL;
    const jsize length = env->GetStringLength(value);
    const jchar *chars = env->GetStringChars(value, nullptr);
    if (!chars) return ENOMEM;

    struct Utf16CharsGuard {
        JNIEnv *env;
        jstring value;
        const jchar *chars;
        ~Utf16CharsGuard() {
            if (chars) env->ReleaseStringChars(value, chars);
        }
    } guard{env, value, chars};

    return utf16ToStandardUtf8(
            reinterpret_cast<const char16_t *>(chars),
            static_cast<size_t>(length), output);
}

static jint removePath(JNIEnv* env, jstring path, int (*remove_fn)(const char*)) {
    if (!path) return EINVAL;
    std::string utf8_path;
    const jint conversion_error = jstringToStandardUtf8(env, path, &utf8_path);
    if (conversion_error != 0) return conversion_error;
    if (remove_fn(utf8_path.c_str()) == 0) return 0;
    return errno;
}

extern "C"
JNIEXPORT jint JNICALL
Java_io_github_a13e300_fusefixer_Utils_rmdir(JNIEnv *env, jclass, jstring path) {
    return removePath(env, path, rmdir);
}

extern "C"
JNIEXPORT jint JNICALL
Java_io_github_a13e300_fusefixer_Utils_unlink(JNIEnv *env, jclass, jstring path) {
    return removePath(env, path, unlink);
}
