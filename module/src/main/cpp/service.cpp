#include <unistd.h>
#include <dlfcn.h>
#include <vector>
#include <thread>
#include <shared_mutex>

#include "log.h"
#include "zygisk_next_api.h"

#define IS_A2H_APP_NAME_LIST_SYMBOL "_ZN3qti5audio4core21isA2HAppNameListAllowENSt3__16vectorINS2_12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEENS7_IS9_EEEE.cfi"
#define IS_A2H_MUSIC_APP_SYMBOL "_ZN3qti5audio4core13isA2HMusicAppENSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE.cfi"

static ZygiskNextAPI api_table;
std::shared_mutex g_whitelist_mutex;
std::vector<std::string> g_packages_whitelist;

static bool my_isA2HAppNameListAllow(const std::vector<std::string>& appNameList) {
    std::shared_lock lock(g_whitelist_mutex);

    if (g_packages_whitelist.empty()) {
        return false;
    }

    for (const auto& app : appNameList) {
        auto it = std::find(g_packages_whitelist.begin(), g_packages_whitelist.end(), app);
        if (it != g_packages_whitelist.end()) {
            LOGI("my_isA2HAppNameListAllow: allow %s", app.c_str());
            return true;
        }
    }

    return false;
}

static bool my_isA2HMusicApp(const std::string& appName) {
    std::shared_lock lock(g_whitelist_mutex);

    auto it = std::find(g_packages_whitelist.begin(), g_packages_whitelist.end(), appName);
    if (it != g_packages_whitelist.end()) {
        LOGI("my_isA2HMusicApp: allow %s", appName.c_str());
        return true;
    }

    LOGI("my_isA2HMusicApp: deny %s", appName.c_str());
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
            auto addr = api_table.symbolLookup(resolver, IS_A2H_APP_NAME_LIST_SYMBOL, false, nullptr);

            if (api_table.inlineHook(addr,
                                  (void*)my_isA2HAppNameListAllow,
                                  nullptr) == ZN_SUCCESS) {
                LOGI("Inline hook A2H AppName List SUCCESS");
            } else {
                LOGE("Inline hook A2H AppName List FAILED");
            }

            addr = api_table.symbolLookup(resolver, IS_A2H_MUSIC_APP_SYMBOL, false, nullptr);

            if (api_table.inlineHook(addr,
                                  (void*)my_isA2HMusicApp,
                                  nullptr) == ZN_SUCCESS) {
                LOGI("Inline hook A2H Music App Check SUCCESS");
            } else {
                LOGE("Inline hook A2H Music App Check FAILED");
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

                std::vector<std::string> new_list;
                char* saveptr;
                char* line = strtok_r(&buffer[0], "\n", &saveptr);
                while (line != nullptr) {
                    size_t len = strlen(line);
                    if (len > 0 && line[len-1] == '\r') line[len-1] = '\0';

                    if (strlen(line) > 0) {
                        new_list.emplace_back(line);
                    }
                    line = strtok_r(nullptr, "\n", &saveptr);
                }

                std::unique_lock lock(g_whitelist_mutex);
                g_packages_whitelist = std::move(new_list);
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