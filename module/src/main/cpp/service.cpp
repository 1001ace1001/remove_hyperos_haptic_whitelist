#include <unistd.h>
#include <dlfcn.h>
#include <vector>
#include <thread>
#include <shared_mutex>
#include <unordered_set>

#include "log.h"
#include "zygisk_next_api.h"

#define IS_A2H_MUSIC_APP_SYMBOL "_ZN3qti5audio4core13isA2HMusicAppENSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE.cfi"

static ZygiskNextAPI api_table;
std::shared_mutex pointer_swap_lock;
std::unordered_set<std::string> *g_packages_whitelist = nullptr;

static bool AnalyzeA2HMusicAppWhiteListAddress(void *isA2HMusicApp_addr) {
    void *a2h_music_app_whitelist_address = nullptr;

    auto *func_ptr = static_cast<uint32_t *>(isA2HMusicApp_addr);
    if (func_ptr == nullptr) {
        return false;
    }

    LOGI("Start searching A2HMusicAppWhiteListAddress");

    for (int i = 0; i < 30; i++) {
        const uint32_t inst = func_ptr[i];

        if ((inst & 0x9F000000) == 0x10000000) { // search ADR
            LOGI("ADR searched");

            const uint32_t *pc = &func_ptr[i];

            const uint32_t immlo = (inst >> 29) & 0x3U;
            const uint32_t immhi = (inst >> 5) & 0x7FFFFU;

            auto imm21 = static_cast<int32_t>((immhi << 2) | immlo);

            if ((imm21 & 0x100000) != 0) {
                imm21 |= static_cast<int32_t>(0xFFE00000);
            }

            a2h_music_app_whitelist_address = reinterpret_cast<void **>(
                    reinterpret_cast<uintptr_t>(pc) + static_cast<uintptr_t>(imm21)
            );

            LOGI("whitelist_address: %p", a2h_music_app_whitelist_address);
            break;
        }
    }

    if (a2h_music_app_whitelist_address != nullptr) {
        pointer_swap_lock.lock();
        std::unordered_set<std::string> *old_whitelist = nullptr;
        old_whitelist = g_packages_whitelist;
        g_packages_whitelist = reinterpret_cast<std::unordered_set<std::string> *>(a2h_music_app_whitelist_address);

        if (old_whitelist != nullptr) {
            *g_packages_whitelist = std::move(*old_whitelist);
            delete old_whitelist;
        }
        pointer_swap_lock.unlock();

        return true;
    }

    return false;
}

static void* (*orig_do_dlopen)(const char* name, int flags, const void* extinfo, const void* caller_addr) = nullptr;
void* do_dlopen_addr = nullptr;

static void* my_do_dlopen(const char* name, int flags, const void* extinfo, const void* caller_addr) {
    void* library_handle = orig_do_dlopen(name, flags, extinfo, caller_addr);

    if (strstr(name, "libaudiocorehal.qti.so")) {
        LOGI("target library %s loaded", name);

        auto resolver = api_table.newSymbolResolver(name, nullptr);
        if (resolver) {
            auto addr = api_table.symbolLookup(resolver, IS_A2H_MUSIC_APP_SYMBOL, false, nullptr);

            if (AnalyzeA2HMusicAppWhiteListAddress(addr)) {
                LOGI("A2H MusicApp Whitelist Address found!");
            } else {
                LOGE("A2H MusicApp WhiteList Address search FAILED!");
            }

            api_table.freeSymbolResolver(resolver);
        } else {
            LOGE("Failed to create resolver");
        }

        if (api_table.inlineUnhook(do_dlopen_addr) == ZN_SUCCESS) {
            LOGI("Inline hook unhook do_dlopen SUCCESS");
        } else {
            LOGE("Inline hook unhook do_dlopen FAILED");
        }
    }

    return library_handle;
}

/**
 * Start a daemon thread to process the notification from companion.
 * @param fd companion fd
 */
void start_rpc_receiver(int fd) {
    std::thread([fd]() {
        while (true) {
            uint32_t data_size = 0;
            ssize_t r = read(fd, &data_size, sizeof(data_size));
            if (r <= 0) break;

            LOGI("received notification from companion!");

            if (data_size > 0 && data_size < 1024 * 64) {
                std::string buffer;
                buffer.resize(data_size);

                ssize_t total_read = 0;
                while (total_read < data_size) {
                    ssize_t curr = read(fd, &buffer[0] + total_read, data_size - total_read);
                    if (curr <= 0) return;
                    total_read += curr;
                }

                std::unordered_set<std::string> new_list;
                char* saveptr;
                char* line = strtok_r(&buffer[0], "\n", &saveptr);

                while (line != nullptr) {
                    size_t len = strlen(line);
                    if (len > 0 && line[len - 1] == '\r') {
                        line[len - 1] = '\0';
                    }

                    if (line[0] != '\0') {
                        new_list.insert(std::string(line));
                    }
                    line = strtok_r(nullptr, "\n", &saveptr);
                }

                if (g_packages_whitelist == nullptr) {
                    pointer_swap_lock.lock();
                    g_packages_whitelist = new std::unordered_set<std::string>();
                    *g_packages_whitelist = std::move(new_list);
                    pointer_swap_lock.unlock();
                } else {
                    *g_packages_whitelist = std::move(new_list);
                }

                LOGI("whitelist updated");
            }
        }
        close(fd);
    }).detach();
}

void onModuleLoaded(void* self_handle, const struct ZygiskNextAPI* api) {
    memcpy(&api_table, api, sizeof(struct ZygiskNextAPI));

    LOGI("module loaded");

    auto linker_resolver = api->newSymbolResolver("linker64", nullptr);

    if (linker_resolver) {
        do_dlopen_addr = api->symbolLookup(linker_resolver, "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv", false, nullptr);

        if (do_dlopen_addr) {
            api->inlineHook(do_dlopen_addr, (void*) my_do_dlopen, (void**)&orig_do_dlopen);
            LOGI("Inline hook do_dlopen success");
        } else {
            LOGI("Inline hook do_dlopen failed");
        }
        api->freeSymbolResolver(linker_resolver);
    } else {
        LOGI("Failed to create linker resolver");
    }

    start_rpc_receiver(api_table.connectCompanion(self_handle));
}

// declaration of the zygisk next module
__attribute__((visibility("default"), unused))
struct ZygiskNextModule zn_module = {
        .target_api_version = ZYGISK_NEXT_API_VERSION_1,
        .onModuleLoaded = onModuleLoaded
};