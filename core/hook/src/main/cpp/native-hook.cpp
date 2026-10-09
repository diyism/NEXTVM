/**
 * NEXTVM Native Hook Library
 *
 * PLT/GOT hooks for libc file I/O functions to implement native-level
 * path redirection for guest app file isolation.
 *
 * Hooks (installed via GOT patching):
 *   - open/openat     → redirect file paths to sandbox
 *   - access          → check sandbox path instead
 *   - stat/lstat      → stat sandbox path instead
 *   - readlink        → return sandbox path
 *   - fopen           → redirect file paths to sandbox
 *   - __system_property_get → spoof device properties
 *
 * Architecture:
 *   Java (NativeHookBridge.kt)
 *     ↓ JNI
 *   native-hook.cpp (this file)
 *     ↓ GOT/PLT patching via dl_iterate_phdr + ELF parsing
 *   hooked libc functions ←→ original libc functions (via saved pointers)
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <dirent.h>

// Define ELF_R_SYM if not provided by NDK headers
#ifndef ELF_R_SYM
#ifdef __LP64__
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#endif
#endif

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <cerrno>
#include <signal.h>
#include <setjmp.h>
#include <sys/syscall.h>
#include <android/dlext.h>

#ifndef SYS_memfd_create
#  if defined(__aarch64__)
#    define SYS_memfd_create 279
#  elif defined(__arm__)
#    define SYS_memfd_create 385
#  elif defined(__x86_64__)
#    define SYS_memfd_create 319
#  endif
#endif

#ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 0x0001U
#endif

#define LOG_TAG "NextVM-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== Global State ====================

static bool g_initialized = false;
static bool g_hooks_installed = false;
static std::mutex g_mutex;

// Path redirection: source prefix → target prefix
static std::unordered_map<std::string, std::string> g_path_redirects;

// Property spoofing: property name → spoofed value
static std::unordered_map<std::string, std::string> g_property_spoofs;

// Hidden paths: paths that should appear non-existent
static std::unordered_set<std::string> g_hidden_paths;

// /proc/self spoofing
static int g_spoofed_pid = -1;
static std::string g_spoofed_package_name;

// Host package data dir prefix
static std::string g_host_data_prefix;

// Virtual data root
static std::string g_virtual_data_root;

// ==================== Original Function Pointers ====================

typedef int (*orig_open_t)(const char*, int, ...);
typedef int (*orig_openat_t)(int, const char*, int, ...);
typedef int (*orig_access_t)(const char*, int);
typedef int (*orig_stat_t)(const char*, struct stat*);
typedef int (*orig_lstat_t)(const char*, struct stat*);
typedef ssize_t (*orig_readlink_t)(const char*, char*, size_t);
typedef FILE* (*orig_fopen_t)(const char*, const char*);
typedef int (*orig_system_property_get_t)(const char*, char*);

static orig_open_t real_open = nullptr;
static orig_openat_t real_openat = nullptr;
static orig_access_t real_access = nullptr;
static orig_stat_t real_stat = nullptr;
static orig_lstat_t real_lstat = nullptr;
static orig_readlink_t real_readlink = nullptr;
static orig_fopen_t real_fopen = nullptr;
static orig_system_property_get_t real_system_property_get = nullptr;

typedef void* (*orig_dlopen_t)(const char*, int);
typedef void* (*orig_android_dlopen_ext_t)(const char*, int, const android_dlextinfo*);

static orig_dlopen_t real_dlopen = nullptr;
static orig_android_dlopen_ext_t real_android_dlopen_ext = nullptr;

// Defined in the GOT/PLT section below: re-runs the patch pass so that
// libraries loaded after nativeInit (e.g. a packer shell's .so brought in
// via System.loadLibrary) receive the same GOT hooks as startup libraries.
static void patch_newly_loaded_libraries();

// ==================== Path Redirection Logic ====================

/**
 * Check if a path is hidden.
 */
static bool is_path_hidden(const char* path) {
    if (path == nullptr || g_hidden_paths.empty()) return false;
    return g_hidden_paths.count(std::string(path)) > 0;
}

/**
 * Check if a path needs redirection and return the redirected path.
 * Returns empty string if no redirection needed.
 */
static std::string redirect_path(const char* path) {
    if (path == nullptr || path[0] == '\0') return "";
    if (g_path_redirects.empty()) return "";

    std::string path_str(path);

    // Check each registered redirect prefix (longest match wins)
    std::string best_from;
    std::string best_to;
    for (const auto& redirect : g_path_redirects) {
        if (path_str.compare(0, redirect.first.length(), redirect.first) == 0) {
            if (redirect.first.length() > best_from.length()) {
                best_from = redirect.first;
                best_to = redirect.second;
            }
        }
    }

    if (!best_from.empty()) {
        return best_to + path_str.substr(best_from.length());
    }

    // Special case: /data/user/0/ is the same as /data/data/
    if (path_str.compare(0, 13, "/data/user/0/") == 0) {
        std::string alt_path = "/data/data/" + path_str.substr(13);
        return redirect_path(alt_path.c_str());
    }

    return "";
}

/**
 * Check if a path is a /proc/self path that needs spoofing.
 */
static bool is_proc_self_path(const char* path) {
    if (path == nullptr) return false;
    return strncmp(path, "/proc/self/", 11) == 0;
}

// ==================== Hook Implementations ====================

// ==================== /proc/self Spoof Content ====================

enum ProcSpoofKind {
    PROC_SPOOF_NONE = 0,
    PROC_SPOOF_CMDLINE,
    PROC_SPOOF_MAPS,
    PROC_SPOOF_COMM,
    PROC_SPOOF_STATUS,
    PROC_SPOOF_STAT
};

// Keywords that betray the virtual environment in /proc/self/maps.
// Shared by the fopen() and open()/openat() spoof paths.
static bool maps_line_visible(const char* line) {
    static const char* kHiddenKeywords[] = {
        "nextvm", "lsplant", "dobby", "bhook", "xhook", "substrate", "xposed"
    };
    for (const char* kw : kHiddenKeywords) {
        if (strstr(line, kw) != nullptr) return false;
    }
    return true;
}

// Synthetic "normal install" locations used to rewrite the guest's own
// mappings in /proc/self/maps. A stock device shows the guest APK under
// /data/app/~~<rand>==/<pkg>-<rand>==/base.apk with its extracted libs in
// the sibling lib/arm64 directory — mirror that shape (constant tokens
// are fine; what matters is that the paths stop betraying the virtual
// layout and stop containing the host's package name).
static std::string synthetic_apk_path() {
    return "/data/app/~~VmK8x2==/" + g_spoofed_package_name + "-VmK8x2==/base.apk";
}

static std::string synthetic_lib_path(const std::string& file_name) {
    return "/data/app/~~VmK8x2==/" + g_spoofed_package_name +
           "-VmK8x2==/lib/arm64/" + file_name;
}

/**
 * Rewrite a filesystem path that betrays the virtual layout into its
 * stock-install equivalent. Shared by the maps transform and by the
 * readlink result rewriting (fd symlink targets). Returns false when
 * the path needs no rewrite. When the path belongs to the host/engine
 * itself (no guest-side equivalent exists), *host_fallback is set and
 * `out` receives the synthetic APK path as a plausible stand-in —
 * callers that present listings (maps) should drop such entries
 * instead, callers that must return a path (readlink) use the stand-in.
 */
static bool rewrite_virtual_path(const std::string& path, std::string& out,
                                 bool* host_fallback = nullptr) {
    if (host_fallback != nullptr) *host_fallback = false;
    std::string core = path;
    std::string suffix;
    if (core.size() >= 11 &&
        core.compare(core.size() - 11, 11, " (deleted)") == 0) {
        core.erase(core.size() - 11);
        suffix = " (deleted)";
    }

    // Guest APK files: base + split APKs (virtual storage names splits
    // "<instanceId>_split_config.<...>.apk"; stock form is the plain
    // split file name next to base.apk).
    if (core.find("/files/virtual/apks/") != std::string::npos &&
        core.size() >= 4 && core.compare(core.size() - 4, 4, ".apk") == 0) {
        std::string fname = core.substr(core.find_last_of('/') + 1);
        size_t split_pos = fname.find("split_");
        if (fname.find("_split_") != std::string::npos &&
            split_pos != std::string::npos) {
            out = "/data/app/~~VmK8x2==/" + g_spoofed_package_name +
                  "-VmK8x2==/" + fname.substr(split_pos) + suffix;
        } else {
            out = synthetic_apk_path() + suffix;
        }
        return true;
    }

    // Guest data tree: extracted libs go to the synthetic lib dir,
    // everything else mirrors under /data/data/<pkg>/.
    const std::string data_marker = "/files/virtual/data/";
    size_t data_pos = core.find(data_marker);
    if (data_pos != std::string::npos) {
        size_t inst_end = core.find('/', data_pos + data_marker.size());
        if (inst_end != std::string::npos) {
            std::string rest = core.substr(inst_end + 1);
            if (rest.compare(0, 4, "lib/") == 0) {
                out = synthetic_lib_path(
                    rest.substr(rest.find_last_of('/') + 1)) + suffix;
            } else {
                out = "/data/data/" + g_spoofed_package_name + "/" + rest +
                      suffix;
            }
            return true;
        }
    }

    // Anything else naming the host app is the engine/host itself.
    if (core.find("nextvm") != std::string::npos) {
        if (host_fallback != nullptr) *host_fallback = true;
        out = synthetic_apk_path() + suffix;
        return true;
    }
    return false;
}

/**
 * Transform one /proc/self/maps line for the spoofed view.
 * Returns false if the line must be dropped; otherwise fills `out`.
 *
 * v1 of this spoof simply dropped every line mentioning the host —
 * including the guest's OWN apk/lib mappings (they live under the
 * host's data dir), so a shell locating itself or its APK in maps
 * found nothing at all. v2 rewrites the guest's own paths to a
 * plausible stock-install layout and only drops lines that belong to
 * the host app / hook engine itself.
 */
static bool transform_maps_line(const char* line, std::string& out) {
    const char* slash = strchr(line, '/');
    if (slash != nullptr) {
        std::string prefix(line, static_cast<size_t>(slash - line));
        std::string core(slash);
        while (!core.empty() && (core.back() == '\n' || core.back() == '\r')) {
            core.pop_back();
        }

        std::string rewritten;
        bool host_fallback = false;
        if (rewrite_virtual_path(core, rewritten, &host_fallback)) {
            // Host/engine mappings have no guest-side equivalent; a
            // stock process simply has no such lines — drop them.
            if (host_fallback) return false;
            out = prefix + rewritten + "\n";
            return true;
        }
    }

    // Hook-framework keywords anywhere in the line (also covers
    // [anon:...] mapping names) — drop.
    if (!maps_line_visible(line)) return false;

    out = line;
    return true;
}

static std::string build_spoofed_maps() {
    std::string result;
    int fd = real_open != nullptr ? real_open("/proc/self/maps", O_RDONLY) : -1;
    if (fd < 0) return result;
    FILE* in = fdopen(fd, "r");
    if (in == nullptr) {
        close(fd);
        return result;
    }
    char line[4096];
    while (fgets(line, sizeof(line), in)) {
        std::string out;
        if (transform_maps_line(line, out)) result += out;
    }
    fclose(in);
    return result;
}

/**
 * Build the spoofed /proc/self/status: the real content with only the
 * Name line replaced. In a guest process Name reads "m.nextvm.app:p0";
 * replace it with the guest's comm (package truncated to 15 chars,
 * consistent with the comm spoof). Uid and TracerPid are kept real so
 * the content stays consistent with getuid() and with the actual
 * (untraced) state — the Java layer's fabricated Uid is NOT reused.
 */
static std::string read_whole_file(const char* path) {
    std::string content;
    int fd = real_open != nullptr ? real_open(path, O_RDONLY) : -1;
    if (fd < 0) return content;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return content;
}

static std::string build_spoofed_status(const char* src_path = nullptr) {
    std::string content = read_whole_file(
        src_path != nullptr ? src_path : "/proc/self/status");

    size_t pos = std::string::npos;
    if (content.compare(0, 6, "Name:\t") == 0) {
        pos = 0;
    } else {
        size_t p = content.find("\nName:\t");
        if (p != std::string::npos) pos = p + 1;
    }
    if (pos != std::string::npos) {
        size_t line_end = content.find('\n', pos);
        std::string name_line = "Name:\t" + g_spoofed_package_name.substr(0, 15);
        if (line_end == std::string::npos) {
            content = content.substr(0, pos) + name_line + "\n";
        } else {
            content = content.substr(0, pos) + name_line + content.substr(line_end);
        }
    }
    return content;
}

/**
 * Build the spoofed /proc/<pid>/stat (also serves task/<main-tid>/stat):
 * the real content with the parenthesised comm field replaced by the
 * guest's comm. Every other field (pid, timings, sizes) stays real.
 */
static std::string build_spoofed_stat(const char* src_path = nullptr) {
    std::string content = read_whole_file(
        src_path != nullptr ? src_path : "/proc/self/stat");
    size_t open = content.find('(');
    size_t close = content.rfind(')');
    if (open != std::string::npos && close != std::string::npos && close > open) {
        content = content.substr(0, open + 1) +
                  g_spoofed_package_name.substr(0, 15) +
                  content.substr(close);
    }
    return content;
}

/**
 * Classify a path as a spoofable /proc file (cmdline/maps/comm) for this
 * process — matches both /proc/self/<file> and /proc/<own-pid>/<file>.
 * Returns PROC_SPOOF_NONE when no spoofing applies (including when the
 * Java side never armed spoofing via nativeSpoofProcSelf).
 */
static ProcSpoofKind match_proc_spoof(const char* path) {
    if (path == nullptr || g_spoofed_package_name.empty()) return PROC_SPOOF_NONE;

    const char* base = nullptr;
    long owner_pid = -1;  // pid the requested file describes
    if (strncmp(path, "/proc/self/", 11) == 0) {
        base = path + 11;
        owner_pid = static_cast<long>(getpid());
    } else if (strncmp(path, "/proc/", 6) == 0) {
        char* end = nullptr;
        long pid = strtol(path + 6, &end, 10);
        if (end != nullptr && *end == '/') {
            // Own pid — or the armed guest process's pid, which is what
            // a forked child of the guest reads when it inspects its
            // parent (dual-process checks). The stub's own parent (the
            // zygote) deliberately does NOT match in the armed process
            // itself, because there owner references use getpid().
            if (pid == static_cast<long>(getpid()) ||
                pid == static_cast<long>(g_spoofed_pid)) {
                base = end + 1;
                owner_pid = pid;
            }
        }
    }
    if (base == nullptr) return PROC_SPOOF_NONE;

    if (strcmp(base, "cmdline") == 0) return PROC_SPOOF_CMDLINE;
    if (strcmp(base, "maps") == 0) return PROC_SPOOF_MAPS;
    if (strcmp(base, "comm") == 0) return PROC_SPOOF_COMM;
    if (strcmp(base, "status") == 0) return PROC_SPOOF_STATUS;
    if (strcmp(base, "stat") == 0) return PROC_SPOOF_STAT;

    // /proc/<pid>/task/<tid>/<file>: threads share the process cmdline,
    // so that leaf spoofs for every tid. comm/status/stat only betray
    // the guest for the MAIN thread (tid == pid), whose name is the
    // stub's "m.nextvm.app:pN"; the other threads carry generic ART
    // names identical to a stock app process and pass through real.
    if (strncmp(base, "task/", 5) == 0) {
        char* end = nullptr;
        long tid = strtol(base + 5, &end, 10);
        if (end != nullptr && *end == '/') {
            const char* leaf = end + 1;
            if (strcmp(leaf, "cmdline") == 0) return PROC_SPOOF_CMDLINE;
            if (tid == owner_pid) {
                if (strcmp(leaf, "comm") == 0) return PROC_SPOOF_COMM;
                if (strcmp(leaf, "status") == 0) return PROC_SPOOF_STATUS;
                if (strcmp(leaf, "stat") == 0) return PROC_SPOOF_STAT;
            }
        }
    }
    return PROC_SPOOF_NONE;
}

static bool write_all_fd(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

/**
 * Create an anonymous in-memory fd pre-filled with the spoofed content
 * for the given /proc file, positioned at offset 0. Falls back to a
 * tmpfile when memfd is unavailable. Returns -1 on failure.
 */
static int make_proc_spoof_fd(ProcSpoofKind kind, const char* src_path = nullptr) {
    int fd = -1;
#ifdef SYS_memfd_create
    fd = static_cast<int>(syscall(SYS_memfd_create, "proc", MFD_CLOEXEC));
#endif
    FILE* tmp = nullptr;
    if (fd < 0) {
        tmp = tmpfile();
        if (tmp == nullptr) return -1;
        fd = fileno(tmp);
    }

    bool ok = true;
    if (kind == PROC_SPOOF_CMDLINE) {
        ok = write_all_fd(fd, g_spoofed_package_name.c_str(),
                          g_spoofed_package_name.length() + 1);
    } else if (kind == PROC_SPOOF_COMM) {
        std::string comm = g_spoofed_package_name.substr(0, 15) + "\n";
        ok = write_all_fd(fd, comm.c_str(), comm.length());
    } else if (kind == PROC_SPOOF_MAPS) {
        std::string content = build_spoofed_maps();
        ok = !content.empty() && write_all_fd(fd, content.data(), content.size());
    } else if (kind == PROC_SPOOF_STATUS) {
        std::string content = build_spoofed_status(src_path);
        ok = !content.empty() && write_all_fd(fd, content.data(), content.size());
    } else if (kind == PROC_SPOOF_STAT) {
        std::string content = build_spoofed_stat(src_path);
        ok = !content.empty() && write_all_fd(fd, content.data(), content.size());
    }

    if (!ok) {
        if (tmp != nullptr) fclose(tmp); else close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    if (tmp != nullptr) {
        // dup so the caller owns an fd independent of the tmpfile's FILE;
        // the shared offset was just rewound to 0.
        int out = dup(fd);
        fclose(tmp);
        fd = out;
    }

    if (fd >= 0) {
        static int logged_cmdline = 0, logged_maps = 0, logged_comm = 0, logged_status = 0, logged_stat = 0;
        int* counter = &logged_cmdline;
        const char* name = "cmdline";
        if (kind == PROC_SPOOF_MAPS) { counter = &logged_maps; name = "maps"; }
        else if (kind == PROC_SPOOF_COMM) { counter = &logged_comm; name = "comm"; }
        else if (kind == PROC_SPOOF_STATUS) { counter = &logged_status; name = "status"; }
        else if (kind == PROC_SPOOF_STAT) { counter = &logged_stat; name = "stat"; }
        if (*counter < 3) {
            (*counter)++;
            LOGI("open: served spoofed /proc/self/%s (pkg=%s)", name,
                 g_spoofed_package_name.c_str());
        }
    }
    return fd;
}

/**
 * Hooked open() — redirects file paths to sandbox, hides paths.
 */
static int hooked_open(const char* path, int flags, ...) {
    // Check hidden paths
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    // Serve spoofed /proc/self files — packer shells read cmdline/maps
    // via open() during their environment checks, long before any Java
    // code runs. Only fopen() was spoofed previously, which native code
    // rarely uses.
    if ((flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind kind = match_proc_spoof(path);
        if (kind != PROC_SPOOF_NONE) {
            int fd = make_proc_spoof_fd(kind, path);
            if (fd >= 0) return fd;
        }
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    if (!redirected.empty()) {
        LOGD("open: %s -> %s", path, actual_path);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
        return real_open(actual_path, flags, mode);
    }
    return real_open(actual_path, flags);
}

/**
 * Hooked openat() — redirects file paths to sandbox, hides paths.
 */
static int hooked_openat(int dirfd, const char* path, int flags, ...) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    // Serve spoofed /proc/self files for absolute paths (dirfd is
    // ignored for absolute paths by the kernel anyway).
    if (path != nullptr && path[0] == '/' && (flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind kind = match_proc_spoof(path);
        if (kind != PROC_SPOOF_NONE) {
            int fd = make_proc_spoof_fd(kind, path);
            if (fd >= 0) return fd;
        }
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    if (!redirected.empty()) {
        LOGD("openat: %s -> %s", path, actual_path);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
        return real_openat(dirfd, actual_path, flags, mode);
    }
    return real_openat(dirfd, actual_path, flags);
}

/**
 * Hooked access() — checks sandbox path instead, hides paths.
 */
static int hooked_access(const char* path, int mode) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    return real_access(actual_path, mode);
}

/**
 * Hooked stat() — stats sandbox path instead, hides paths.
 */
static int hooked_stat(const char* path, struct stat* buf) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    return real_stat(actual_path, buf);
}

/**
 * Hooked lstat() — lstats sandbox path instead, hides paths.
 */
static int hooked_lstat(const char* path, struct stat* buf) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    return real_lstat(actual_path, buf);
}

/**
 * Hooked readlink() — returns sandbox path instead.
 */
static ssize_t hooked_readlink(const char* path, char* buf, size_t bufsiz) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    // Spoof /proc/self/exe
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/exe") == 0 &&
        !g_spoofed_package_name.empty()) {
        // Return a fake exe path
        std::string fake = "/system/bin/app_process64";
        size_t len = fake.length();
        if (len > bufsiz) len = bufsiz;
        memcpy(buf, fake.c_str(), len);
        return static_cast<ssize_t>(len);
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    ssize_t n = real_readlink(actual_path, buf, bufsiz);
    // When spoofing is armed, rewrite the RESULT if it names a virtual
    // path. Directory enumerators learn the world from readlink targets
    // (above all the /proc/*/fd symlink walk a packer shell performs),
    // not from the paths passed in — fd targets must not leak the host
    // layout, other guests' identities, or the word "virtual".
    if (n > 0 && !g_spoofed_package_name.empty()) {
        std::string target(buf, static_cast<size_t>(n));
        std::string rewritten;
        if (rewrite_virtual_path(target, rewritten)) {
            size_t len = rewritten.length();
            if (len > bufsiz) len = bufsiz;
            memcpy(buf, rewritten.c_str(), len);
            static int logged = 0;
            if (logged < 5) {
                logged++;
                LOGI("readlink: rewrote target %s -> %s",
                     target.c_str(), rewritten.c_str());
            }
            return static_cast<ssize_t>(len);
        }
    }
    return n;
}

/**
 * Hooked fopen() — redirects file paths to sandbox, hides paths.
 */
static FILE* hooked_fopen(const char* path, const char* mode) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return nullptr;
    }

    // Spoof /proc/<pid>/stat and /proc/<pid>/task/<tid>/{cmdline,comm,
    // status,stat} through the shared matcher — the per-file branches
    // below only cover the top-level /proc/self forms.
    {
        ProcSpoofKind kind = match_proc_spoof(path);
        if (kind == PROC_SPOOF_STAT ||
            (kind != PROC_SPOOF_NONE && strstr(path, "/task/") != nullptr)) {
            int fd = make_proc_spoof_fd(kind, path);
            if (fd >= 0) {
                FILE* f = fdopen(fd, mode != nullptr ? mode : "r");
                if (f != nullptr) return f;
                close(fd);
            }
        }
    }

    // Spoof /proc/self/cmdline
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/cmdline") == 0 &&
        !g_spoofed_package_name.empty()) {
        // Create a temp file with spoofed cmdline
        FILE* tmp = tmpfile();
        if (tmp) {
            fwrite(g_spoofed_package_name.c_str(), 1, g_spoofed_package_name.length() + 1, tmp);
            fseek(tmp, 0, SEEK_SET);
            return tmp;
        }
    }

    // Spoof /proc/self/comm
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/comm") == 0 &&
        !g_spoofed_package_name.empty()) {
        FILE* tmp = tmpfile();
        if (tmp) {
            std::string comm = g_spoofed_package_name.substr(0, 15) + "\n";
            fwrite(comm.c_str(), 1, comm.length(), tmp);
            fseek(tmp, 0, SEEK_SET);
            return tmp;
        }
    }

    // Spoof /proc/self/maps — guest paths rewritten to a stock-install
    // layout, host/engine lines dropped (shared with the open() path)
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/maps") == 0 &&
        !g_spoofed_package_name.empty()) {
        std::string content = build_spoofed_maps();
        if (!content.empty()) {
            FILE* tmp = tmpfile();
            if (tmp) {
                fwrite(content.data(), 1, content.size(), tmp);
                fseek(tmp, 0, SEEK_SET);
                return tmp;
            }
        }
    }

    // Spoof /proc/self/status — real content, Name line replaced
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/status") == 0 &&
        !g_spoofed_package_name.empty()) {
        std::string content = build_spoofed_status();
        if (!content.empty()) {
            FILE* tmp = tmpfile();
            if (tmp) {
                fwrite(content.data(), 1, content.size(), tmp);
                fseek(tmp, 0, SEEK_SET);
                return tmp;
            }
        }
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    if (!redirected.empty()) {
        LOGD("fopen: %s -> %s", path, actual_path);
    }

    return real_fopen(actual_path, mode);
}

/**
 * Hooked __system_property_get() — returns spoofed device properties.
 */
static int hooked_system_property_get(const char* name, char* value) {
    // Check if we have a spoofed value for this property
    if (name != nullptr && !g_property_spoofs.empty()) {
        std::string prop_name(name);
        auto it = g_property_spoofs.find(prop_name);
        if (it != g_property_spoofs.end()) {
            const std::string& spoofed = it->second;
            size_t len = spoofed.length();
            if (len > 91) len = 91; // PROP_VALUE_MAX - 1
            memcpy(value, spoofed.c_str(), len);
            value[len] = '\0';
            LOGD("property_get: %s -> %s (spoofed)", name, value);
            return static_cast<int>(len);
        }
    }

    // No spoof — call real implementation
    return real_system_property_get(name, value);
}

/**
 * Hooked dlopen() — after a successful load, patch the GOTs of any
 * libraries that just arrived. Packer shells (e.g. SecNeo's
 * libDexHelper.so) are dlopen'd by the guest Application long after
 * nativeInit's one-shot patch pass; without this, none of the hooks —
 * including the /proc/self spoofing — apply to the shell's own calls.
 */
static void* hooked_dlopen(const char* filename, int flags) {
    void* handle = real_dlopen != nullptr ? real_dlopen(filename, flags) : nullptr;
    if (handle != nullptr) {
        patch_newly_loaded_libraries();
    }
    return handle;
}

/**
 * Hooked android_dlopen_ext() — same late-patch behavior as dlopen.
 * This is the entry point the native loader itself uses for
 * namespaced library loads (System.loadLibrary).
 */
static void* hooked_android_dlopen_ext(const char* filename, int flags,
                                       const android_dlextinfo* extinfo) {
    void* handle = real_android_dlopen_ext != nullptr
        ? real_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (handle != nullptr) {
        patch_newly_loaded_libraries();
    }
    return handle;
}

// ==================== Diagnostic hooks (log-only) ====================
//
// Identify which environment channel a packer shell actually uses
// before dying: dl_iterate_phdr (library enumeration that bypasses all
// /proc spoofing), ptrace + fork (dual-process anti-debug dance),
// syscall (raw syscalls that bypass the PLT hooks on open/openat), and
// opendir (directory enumeration; its libc-internal openat also
// bypasses our PLT hooks). These hooks NEVER alter behaviour: they log
// (rate limited, caller attributed via dladdr) and forward to the real
// implementation.

typedef int (*orig_dl_iterate_phdr_t)(int (*)(struct dl_phdr_info*, size_t, void*), void*);
typedef long (*orig_ptrace_t)(int, ...);
typedef long (*orig_syscall_t)(long, ...);
typedef pid_t (*orig_fork_t)();
typedef DIR* (*orig_opendir_t)(const char*);

static orig_dl_iterate_phdr_t real_dl_iterate_phdr = nullptr;
static orig_ptrace_t real_ptrace = nullptr;
static orig_syscall_t real_syscall = nullptr;
static orig_fork_t real_fork = nullptr;
static orig_opendir_t real_opendir = nullptr;

static void diag_caller(void* ret_addr, char* buf, size_t len) {
    Dl_info info;
    if (ret_addr != nullptr && dladdr(ret_addr, &info) && info.dli_fname != nullptr) {
        const char* base = strrchr(info.dli_fname, '/');
        snprintf(buf, len, "%s", base != nullptr ? base + 1 : info.dli_fname);
    } else {
        snprintf(buf, len, "?");
    }
}

static int hooked_dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*),
                                  void* data) {
    static int logged = 0;
    if (logged < 10) {
        logged++;
        char who[128], cb_who[128];
        diag_caller(__builtin_return_address(0), who, sizeof(who));
        diag_caller((void*)callback, cb_who, sizeof(cb_who));
        LOGI("DIAG dl_iterate_phdr called by %s (callback in %s)", who, cb_who);
    }
    if (real_dl_iterate_phdr) return real_dl_iterate_phdr(callback, data);
    return -1;
}

static long hooked_ptrace(int request, ...) {
    va_list ap;
    va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void* addr = va_arg(ap, void*);
    void* data = va_arg(ap, void*);
    va_end(ap);
    static int logged = 0;
    if (logged < 30) {
        logged++;
        char who[128];
        diag_caller(__builtin_return_address(0), who, sizeof(who));
        LOGI("DIAG ptrace req=%d pid=%d addr=%p data=%p by %s",
             request, (int)pid, addr, data, who);
    }
    if (real_ptrace) return real_ptrace(request, pid, addr, data);
    errno = ENOSYS;
    return -1;
}

static long hooked_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    static __thread bool in_hook = false;
    if (!in_hook) {
        in_hook = true;
        // aarch64 numbers of interest: faccessat=48, openat=56, close=57,
        // getdents64=61, read=63, pread64=67, readlinkat=78,
        // newfstatat=79, ptrace=117, kill=129, tgkill=131, clone=220
        bool interesting = number == 48 || number == 56 || number == 57 ||
                           number == 61 || number == 63 || number == 67 ||
                           number == 78 || number == 79 || number == 117 ||
                           number == 129 || number == 131 || number == 220;
        static int logged_int = 0, logged_other = 0;
        if ((interesting && logged_int < 40) || (!interesting && logged_other < 10)) {
            if (interesting) logged_int++; else logged_other++;
            char who[128];
            diag_caller(__builtin_return_address(0), who, sizeof(who));
            if (number == 56 && a2 != 0) {
                LOGI("DIAG syscall openat dirfd=%ld path=%s by %s",
                     a1, (const char*)a2, who);
            } else {
                LOGI("DIAG syscall nr=%ld a1=%ld a2=%ld a3=%ld by %s",
                     number, a1, a2, a3, who);
            }
        }
        in_hook = false;
    }
    if (real_syscall) return real_syscall(number, a1, a2, a3, a4, a5, a6);
    errno = ENOSYS;
    return -1;
}

static pid_t hooked_fork() {
    static int logged = 0;
    bool log_it = logged < 10;
    if (log_it) {
        logged++;
        char who[128];
        diag_caller(__builtin_return_address(0), who, sizeof(who));
        LOGI("DIAG fork called by %s (in pid %d)", who, (int)getpid());
    }
    pid_t r = real_fork ? real_fork() : -1;
    if (log_it) LOGI("DIAG fork returned %d in pid %d", (int)r, (int)getpid());
    return r;
}

static DIR* hooked_opendir(const char* path) {
    if (path != nullptr && strstr(path, "/proc") != nullptr) {
        static int logged = 0;
        if (logged < 20) {
            logged++;
            char who[128];
            diag_caller(__builtin_return_address(0), who, sizeof(who));
            LOGI("DIAG opendir %s by %s", path, who);
        }
    }
    if (real_opendir) return real_opendir(path);
    return nullptr;
}

// ==================== GOT/PLT Hook Installation ====================

// SIGSEGV-safe memory probe: returns false if the address is not readable
static thread_local sigjmp_buf g_probe_jmp;
static thread_local volatile bool g_probing = false;

static void probe_signal_handler(int sig) {
    if (g_probing) {
        siglongjmp(g_probe_jmp, 1);
    }
}

/**
 * Check if a memory address is safely readable using mincore() as a fast check,
 * falling back to a SIGSEGV-safe read probe.
 */
static bool is_address_readable(const void* addr, size_t len) {
    if (addr == nullptr) return false;
    uintptr_t uaddr = reinterpret_cast<uintptr_t>(addr);
    // Reject addresses in the first 64KB (likely relative offsets, not real pointers)
    if (uaddr < 0x10000) return false;

    // Try writing to /proc/self/mem trick — but simplest: use msync as a probe
    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t page_start = uaddr & ~(page_size - 1);
    // msync on a non-mapped page returns -1 with ENOMEM
    if (msync(reinterpret_cast<void*>(page_start), page_size, MS_ASYNC) != 0) {
        return false;
    }
    // Also check the end of the range
    uintptr_t end_page = (uaddr + len - 1) & ~(page_size - 1);
    if (end_page != page_start) {
        if (msync(reinterpret_cast<void*>(end_page), page_size, MS_ASYNC) != 0) {
            return false;
        }
    }
    return true;
}

/**
 * Hook entry: maps a symbol name to our hook function and the saved original pointer.
 */
struct HookEntry {
    const char* symbol;
    void* hook_func;
    void** original_func;
};

static HookEntry g_hook_entries[] = {
    {"open",                    (void*)hooked_open,                 (void**)&real_open},
    {"openat",                  (void*)hooked_openat,               (void**)&real_openat},
    {"access",                  (void*)hooked_access,               (void**)&real_access},
    {"stat",                    (void*)hooked_stat,                 (void**)&real_stat},
    {"lstat",                   (void*)hooked_lstat,                (void**)&real_lstat},
    {"readlink",                (void*)hooked_readlink,             (void**)&real_readlink},
    {"fopen",                   (void*)hooked_fopen,                (void**)&real_fopen},
    {"__system_property_get",   (void*)hooked_system_property_get,  (void**)&real_system_property_get},
    {"open64",                  (void*)hooked_open,                 (void**)&real_open},
    {"openat64",                (void*)hooked_openat,               (void**)&real_openat},
    {"fopen64",                 (void*)hooked_fopen,                (void**)&real_fopen},
    {"dlopen",                  (void*)hooked_dlopen,               (void**)&real_dlopen},
    {"android_dlopen_ext",      (void*)hooked_android_dlopen_ext,   (void**)&real_android_dlopen_ext},
    {"dl_iterate_phdr",         (void*)hooked_dl_iterate_phdr,      (void**)&real_dl_iterate_phdr},
    {"ptrace",                  (void*)hooked_ptrace,               (void**)&real_ptrace},
    {"syscall",                 (void*)hooked_syscall,              (void**)&real_syscall},
    {"fork",                    (void*)hooked_fork,                 (void**)&real_fork},
    {"opendir",                 (void*)hooked_opendir,              (void**)&real_opendir},
};
static constexpr int g_hook_count = sizeof(g_hook_entries) / sizeof(g_hook_entries[0]);

/**
 * Replace a single GOT entry.
 * Makes the GOT page writable, swaps the pointer, restores permissions.
 *
 * @param got_addr  Pointer to the GOT entry to patch
 * @param new_func  The hook function to install
 * @param old_func  Output: the original function pointer that was in the GOT
 * @return true on success
 */
static bool patch_got_entry(void** got_addr, void* new_func, void** old_func) {
    if (got_addr == nullptr) return false;
    // Validate the GOT address is in readable memory before dereferencing
    if (!is_address_readable(got_addr, sizeof(void*))) {
        LOGW("GOT addr %p not readable, skipping", got_addr);
        return false;
    }
    if (*got_addr == nullptr) return false;

    // Don't patch if already pointing to our hook
    if (*got_addr == new_func) return true;

    // Save the original
    if (old_func && *old_func == nullptr) {
        *old_func = *got_addr;
    }

    // Calculate page-aligned address
    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t page_start = reinterpret_cast<uintptr_t>(got_addr) & ~(page_size - 1);

    // Make page writable
    if (mprotect(reinterpret_cast<void*>(page_start), page_size,
                 PROT_READ | PROT_WRITE) != 0) {
        LOGE("mprotect RW failed for GOT entry at %p: %s",
             got_addr, strerror(errno));
        return false;
    }

    // Patch the GOT entry
    *got_addr = new_func;

    // Restore page permissions (read-only)
    mprotect(reinterpret_cast<void*>(page_start), page_size, PROT_READ);

    return true;
}

/**
 * Process a single loaded shared object: find its GOT and patch entries.
 *
 * Parses the ELF dynamic section to locate .rel.plt / .rela.plt relocations,
 * then patches GOT entries for our target symbols.
 */
static void patch_library_got(uintptr_t base_addr, const char* lib_name,
                               const ElfW(Dyn)* dynamic) {
    if (dynamic == nullptr) return;

    // Find required dynamic entries
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const ElfW(Rel)* rel_plt = nullptr;
    const ElfW(Rela)* rela_plt = nullptr;
    size_t rel_plt_size = 0;
    size_t rela_plt_size = 0;
    bool use_rela = false;

    for (const ElfW(Dyn)* dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab = reinterpret_cast<const ElfW(Sym)*>(dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(dyn->d_un.d_ptr);
                break;
            case DT_JMPREL:
                // Could be REL or RELA depending on DT_PLTREL
                rel_plt = reinterpret_cast<const ElfW(Rel)*>(dyn->d_un.d_ptr);
                rela_plt = reinterpret_cast<const ElfW(Rela)*>(dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                rel_plt_size = dyn->d_un.d_val;
                rela_plt_size = dyn->d_un.d_val;
                break;
            case DT_PLTREL:
                use_rela = (dyn->d_un.d_val == DT_RELA);
                break;
        }
    }

    if (symtab == nullptr || strtab == nullptr) return;
    if (rel_plt == nullptr && rela_plt == nullptr) return;

    // Normalize dynamic-segment pointers. On Android 17 many libraries keep
    // link-time virtual addresses (offsets relative to the load bias) in their
    // in-memory PT_DYNAMIC entries instead of relocated absolute addresses.
    // Any d_ptr below base_addr is such an offset and must be rebased by the
    // load bias; pointers at/above base_addr are already absolute and are left
    // untouched. The previous code only rebased symtab/strtab when they were
    // below 0x10000 — real offsets are routinely larger than that (e.g.
    // strtab=0x23250), and rela_plt/rel_plt were never rebased at all — so
    // essentially every library failed the readability probes below and was
    // skipped (observed: 354 skipped, 0 hooked on Android 17 / SDK 37).
    if (base_addr == 0) {
        LOGW("Skipping %s: base_addr=0, cannot rebase dynamic pointers", lib_name);
        return;
    }
    auto rebase_ptr = [base_addr](uintptr_t p) -> uintptr_t {
        return (p != 0 && p < base_addr) ? base_addr + p : p;
    };
    symtab = reinterpret_cast<const ElfW(Sym)*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(symtab)));
    strtab = reinterpret_cast<const char*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(strtab)));
    rel_plt = reinterpret_cast<const ElfW(Rel)*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(rel_plt)));
    rela_plt = reinterpret_cast<const ElfW(Rela)*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(rela_plt)));

    // Verify symtab and strtab are actually readable memory
    if (!is_address_readable(symtab, sizeof(ElfW(Sym))) ||
        !is_address_readable(strtab, 1)) {
        LOGW("Skipping %s: symtab(%p) or strtab(%p) not in readable memory",
             lib_name, symtab, strtab);
        return;
    }

    // Also validate relocation table pointer
    if (use_rela && rela_plt) {
        if (!is_address_readable(rela_plt, sizeof(ElfW(Rela)))) {
            LOGW("Skipping %s: rela_plt(%p) not readable", lib_name, rela_plt);
            return;
        }
    } else if (rel_plt) {
        if (!is_address_readable(rel_plt, sizeof(ElfW(Rel)))) {
            LOGW("Skipping %s: rel_plt(%p) not readable", lib_name, rel_plt);
            return;
        }
    }

    if (use_rela && rela_plt != nullptr && rela_plt_size > 0) {
        // Process RELA entries (arm64, x86_64)
        size_t count = rela_plt_size / sizeof(ElfW(Rela));
        for (size_t i = 0; i < count; i++) {
            const ElfW(Rela)& entry = rela_plt[i];
            size_t sym_idx = ELF_R_SYM(entry.r_info);
            if (sym_idx == 0) continue;

            // Validate sym_idx access is safe
            const ElfW(Sym)* sym_entry_ptr = &symtab[sym_idx];
            if (!is_address_readable(sym_entry_ptr, sizeof(ElfW(Sym)))) continue;

            uint32_t st_name = symtab[sym_idx].st_name;
            const char* sym_name = strtab + st_name;
            if (!is_address_readable(sym_name, 1)) continue;
            if (sym_name[0] == '\0') continue;

            // Check if this symbol is one we want to hook
            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sym_name, g_hook_entries[h].symbol) == 0) {
                    void** got_addr = reinterpret_cast<void**>(
                        base_addr + entry.r_offset);
                    if (patch_got_entry(got_addr, g_hook_entries[h].hook_func,
                                       g_hook_entries[h].original_func)) {
                        LOGD("Hooked %s in %s (RELA)", sym_name, lib_name);
                    }
                    break;
                }
            }
        }
    } else if (rel_plt != nullptr && rel_plt_size > 0) {
        // Process REL entries (arm32, x86)
        size_t count = rel_plt_size / sizeof(ElfW(Rel));
        for (size_t i = 0; i < count; i++) {
            const ElfW(Rel)& entry = rel_plt[i];
            size_t sym_idx = ELF_R_SYM(entry.r_info);
            if (sym_idx == 0) continue;

            // Validate sym_idx access is safe
            const ElfW(Sym)* sym_entry_ptr = &symtab[sym_idx];
            if (!is_address_readable(sym_entry_ptr, sizeof(ElfW(Sym)))) continue;

            uint32_t st_name = symtab[sym_idx].st_name;
            const char* sym_name = strtab + st_name;
            if (!is_address_readable(sym_name, 1)) continue;
            if (sym_name[0] == '\0') continue;

            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sym_name, g_hook_entries[h].symbol) == 0) {
                    void** got_addr = reinterpret_cast<void**>(
                        base_addr + entry.r_offset);
                    if (patch_got_entry(got_addr, g_hook_entries[h].hook_func,
                                       g_hook_entries[h].original_func)) {
                        LOGD("Hooked %s in %s (REL)", sym_name, lib_name);
                    }
                    break;
                }
            }
        }
    }
}

// Base addresses already processed by a patch pass. Libraries loaded
// after nativeInit are patched by re-running the pass from the dlopen
// hooks; this set keeps the pass idempotent and cheap.
static std::unordered_set<uintptr_t> g_patched_bases;
static std::mutex g_patch_mutex;

/**
 * dl_iterate_phdr callback — called for each loaded shared object.
 * We find the PT_DYNAMIC segment and use it to locate GOT entries.
 */
static int install_hooks_callback(struct dl_phdr_info* info, size_t /*size*/, void* /*data*/) {
    if (info->dlpi_name == nullptr) return 0;

    // Already processed by an earlier pass — nothing to do.
    if (info->dlpi_addr != 0 && g_patched_bases.count(info->dlpi_addr)) return 0;

    const char* name = info->dlpi_name;

    // Skip empty names (main executable) and our own library
    if (name[0] == '\0') return 0;
    if (strstr(name, "libnextvm") != nullptr) return 0;

    // Skip the linker itself
    if (strstr(name, "linker") != nullptr) return 0;

    // Skip vDSO and other kernel-mapped objects (no valid GOT to patch)
    if (strstr(name, "vdso") != nullptr) return 0;
    if (strstr(name, "[vdso]") != nullptr) return 0;

    // Skip libraries that commonly have RELRO-protected GOTs causing issues
    if (strstr(name, "libart.so") != nullptr) return 0;
    if (strstr(name, "libhwbinder") != nullptr) return 0;

    // Find PT_DYNAMIC segment
    const ElfW(Dyn)* dynamic = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn)*>(
                info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (dynamic != nullptr) {
        patch_library_got(info->dlpi_addr, name, dynamic);
    }

    if (info->dlpi_addr != 0) g_patched_bases.insert(info->dlpi_addr);

    return 0;
}

/**
 * Install GOT/PLT hooks into all currently loaded shared objects.
 */
static bool install_plt_hooks() {
    LOGI("Installing PLT hooks via GOT patching...");

    // Resolve original function pointers first (before hooking)
    if (!real_open)
        real_open = (orig_open_t)dlsym(RTLD_DEFAULT, "open");
    if (!real_openat)
        real_openat = (orig_openat_t)dlsym(RTLD_DEFAULT, "openat");
    if (!real_access)
        real_access = (orig_access_t)dlsym(RTLD_DEFAULT, "access");
    if (!real_stat)
        real_stat = (orig_stat_t)dlsym(RTLD_DEFAULT, "stat");
    if (!real_lstat)
        real_lstat = (orig_lstat_t)dlsym(RTLD_DEFAULT, "lstat");
    if (!real_readlink)
        real_readlink = (orig_readlink_t)dlsym(RTLD_DEFAULT, "readlink");
    if (!real_fopen)
        real_fopen = (orig_fopen_t)dlsym(RTLD_DEFAULT, "fopen");
    if (!real_system_property_get)
        real_system_property_get = (orig_system_property_get_t)dlsym(
            RTLD_DEFAULT, "__system_property_get");
    if (!real_dlopen)
        real_dlopen = (orig_dlopen_t)dlsym(RTLD_DEFAULT, "dlopen");
    if (!real_android_dlopen_ext)
        real_android_dlopen_ext = (orig_android_dlopen_ext_t)dlsym(
            RTLD_DEFAULT, "android_dlopen_ext");
    if (!real_dl_iterate_phdr)
        real_dl_iterate_phdr = (orig_dl_iterate_phdr_t)dlsym(
            RTLD_DEFAULT, "dl_iterate_phdr");
    if (!real_ptrace)
        real_ptrace = (orig_ptrace_t)dlsym(RTLD_DEFAULT, "ptrace");
    if (!real_syscall)
        real_syscall = (orig_syscall_t)dlsym(RTLD_DEFAULT, "syscall");
    if (!real_fork)
        real_fork = (orig_fork_t)dlsym(RTLD_DEFAULT, "fork");
    if (!real_opendir)
        real_opendir = (orig_opendir_t)dlsym(RTLD_DEFAULT, "opendir");

    if (!real_open || !real_openat || !real_access || !real_stat) {
        LOGE("Failed to resolve one or more libc functions via dlsym");
        return false;
    }

    // Iterate all loaded libraries and patch GOT entries
    {
        std::lock_guard<std::mutex> lock(g_patch_mutex);
        dl_iterate_phdr(install_hooks_callback, nullptr);
    }

    LOGI("PLT hooks installed successfully");
    return true;
}

/**
 * Re-run the GOT patch pass so libraries loaded after nativeInit
 * (via dlopen / android_dlopen_ext / Runtime.nativeLoad) receive the
 * same hooks as startup libraries. Idempotent: libraries already
 * processed are skipped via g_patched_bases.
 */
static void patch_newly_loaded_libraries() {
    static thread_local bool in_pass = false;
    if (in_pass || !g_initialized) return;
    in_pass = true;

    size_t added = 0;
    {
        std::lock_guard<std::mutex> lock(g_patch_mutex);
        size_t before = g_patched_bases.size();
        dl_iterate_phdr(install_hooks_callback, nullptr);
        added = g_patched_bases.size() - before;
    }
    if (added > 0) {
        LOGI("Late-patch: GOT hooks applied to %zu newly loaded librar%s",
             added, added == 1 ? "y" : "ies");
    }

    in_pass = false;
}

// ==================== JNI Bridge ====================

extern "C" {

/**
 * Initialize the native hook engine.
 * Resolves original function pointers and installs GOT/PLT hooks.
 */
JNIEXPORT jboolean JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeInit(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_initialized) {
        LOGI("Native hook engine already initialized");
        return JNI_TRUE;
    }

    LOGI("Initializing NEXTVM native hook engine...");

    // Install PLT hooks via GOT patching
    g_hooks_installed = install_plt_hooks();
    if (!g_hooks_installed) {
        LOGW("GOT/PLT hooking failed — falling back to Java-level hooks only");
    }

    g_initialized = true;
    LOGI("Native hook engine initialized (hooks_installed=%d)", g_hooks_installed);
    return JNI_TRUE;
}

/**
 * Add a path redirection rule.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeAddPathRedirection(
    JNIEnv* env, jobject thiz, jstring sourcePath, jstring targetPath)
{
    (void)thiz;
    const char* src = env->GetStringUTFChars(sourcePath, nullptr);
    const char* tgt = env->GetStringUTFChars(targetPath, nullptr);

    if (src && tgt) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_path_redirects[std::string(src)] = std::string(tgt);
        LOGI("Path redirect added: %s -> %s", src, tgt);
    }

    if (src) env->ReleaseStringUTFChars(sourcePath, src);
    if (tgt) env->ReleaseStringUTFChars(targetPath, tgt);
}

/**
 * Remove a path redirection rule.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeRemovePathRedirection(
    JNIEnv* env, jobject thiz, jstring sourcePath)
{
    (void)thiz;
    const char* src = env->GetStringUTFChars(sourcePath, nullptr);

    if (src) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_path_redirects.erase(std::string(src));
        LOGI("Path redirect removed: %s", src);
    }

    if (src) env->ReleaseStringUTFChars(sourcePath, src);
}

/**
 * Clear all path redirection rules.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeClearPathRedirections(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_path_redirects.clear();
    LOGI("All path redirects cleared");
}

/**
 * Set up /proc/self spoofing at native level.
 * Spoofs cmdline, comm, exe, and maps filtering.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSpoofProcSelf(
    JNIEnv* env, jobject thiz, jint pid, jstring packageName)
{
    (void)thiz;
    const char* pkg = env->GetStringUTFChars(packageName, nullptr);
    if (pkg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_spoofed_pid = pid;
        g_spoofed_package_name = std::string(pkg);
        LOGI("/proc/self spoof set: pid=%d, pkg=%s", pid, pkg);
        env->ReleaseStringUTFChars(packageName, pkg);
    }
}

/**
 * Rename the calling thread/process to the guest's process name:
 * prctl(PR_SET_NAME) sets the kernel comm, which is what /proc/self/stat,
 * /proc/self/status (Name), task/<tid>/comm and ps all report. Doing it
 * at the source makes the identity right on channels no read-path hook
 * can cover (e.g. the guest's forked children inspecting their parent,
 * or anything reading /proc from outside the hooked libraries).
 * MUST match Kotlin: nativeSetProcessName(name: String)
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSetProcessName(
    JNIEnv* env, jobject thiz, jstring name)
{
    (void)thiz;
    const char* n = env->GetStringUTFChars(name, nullptr);
    if (n) {
        // Kernel comm holds at most 15 visible chars (TASK_COMM_LEN-1)
        char comm[16];
        strncpy(comm, n, sizeof(comm) - 1);
        comm[sizeof(comm) - 1] = '\0';
        prctl(PR_SET_NAME, comm, 0, 0, 0);
        LOGI("process renamed: comm=%s", comm);
        env->ReleaseStringUTFChars(name, n);
    }
}

/**
 * Override a system property at native level.
 * MUST match Kotlin: nativeSpoofSystemProperty(key: String, value: String)
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSpoofSystemProperty(
    JNIEnv* env, jobject thiz, jstring key, jstring value)
{
    (void)thiz;
    const char* k = env->GetStringUTFChars(key, nullptr);
    const char* v = env->GetStringUTFChars(value, nullptr);

    if (k && v) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_property_spoofs[std::string(k)] = std::string(v);
        LOGI("Property spoof set: %s -> %s", k, v);
    }

    if (k) env->ReleaseStringUTFChars(key, k);
    if (v) env->ReleaseStringUTFChars(value, v);
}

/**
 * Hide a path at native level (return ENOENT on access).
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeHidePath(
    JNIEnv* env, jobject thiz, jstring path)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (p) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_hidden_paths.insert(std::string(p));
        LOGD("Path hidden: %s", p);
        env->ReleaseStringUTFChars(path, p);
    }
}

/**
 * Unhide a path at native level.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeUnhidePath(
    JNIEnv* env, jobject thiz, jstring path)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (p) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_hidden_paths.erase(std::string(p));
        LOGD("Path unhidden: %s", p);
        env->ReleaseStringUTFChars(path, p);
    }
}

/**
 * Clean up all native hooks and state.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeCleanup(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_path_redirects.clear();
    g_property_spoofs.clear();
    g_hidden_paths.clear();
    g_spoofed_pid = -1;
    g_spoofed_package_name.clear();
    g_host_data_prefix.clear();
    g_virtual_data_root.clear();
    // Note: GOT patches remain in place but do nothing without redirect rules
    LOGI("Native hook state cleaned up");
}

/**
 * Set the host data directory prefix.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSetHostDataPrefix(
    JNIEnv* env, jobject thiz, jstring prefix)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(prefix, nullptr);
    if (p) {
        g_host_data_prefix = std::string(p);
        env->ReleaseStringUTFChars(prefix, p);
        LOGI("Host data prefix: %s", g_host_data_prefix.c_str());
    }
}

/**
 * Set the virtual data root directory.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSetVirtualDataRoot(
    JNIEnv* env, jobject thiz, jstring root)
{
    (void)thiz;
    const char* r = env->GetStringUTFChars(root, nullptr);
    if (r) {
        g_virtual_data_root = std::string(r);
        env->ReleaseStringUTFChars(root, r);
        LOGI("Virtual data root: %s", g_virtual_data_root.c_str());
    }
}

/**
 * Get the current redirect count (for debugging).
 */
JNIEXPORT jint JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeGetRedirectCount(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    return static_cast<jint>(g_path_redirects.size());
}

/**
 * Get the current property spoof count (for debugging).
 */
JNIEXPORT jint JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeGetPropertySpoofCount(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    return static_cast<jint>(g_property_spoofs.size());
}

/**
 * Check if the native engine is initialized.
 */
JNIEXPORT jboolean JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeIsInitialized(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    return g_initialized ? JNI_TRUE : JNI_FALSE;
}

// ==================== Runtime.nativeLoad Hook ====================
//
// Jiagu/360-protected apps call Runtime.load0() which delegates to
// Runtime.nativeLoad(String filename, ClassLoader loader, Class caller).
// In the virtual environment, the "caller" Class argument becomes null
// because Jiagu's native code calls System.loadLibrary via JNI reflection
// from a thread where the caller class cannot be resolved.
//
// ART's CheckJNI mode then calls GetObjectArrayElement on NULL (the
// ProtectionDomain array derived from the null caller) → SIGABRT.
//
// Fix: Hook Runtime.nativeLoad at JNI registration level via RegisterNatives.
// If caller==null, synthesize a non-null Class from the classLoader or use
// java.lang.Runtime as a fallback caller.

// Original native implementation saved via method registration replacement
static void* g_orig_nativeLoad_fn = nullptr;

// Type alias matching ART's native signature for Runtime.nativeLoad
// static jni: (JNIEnv*, jclass, jstring filename, jobject classLoader, jclass caller) -> jstring
typedef jstring (*NativeLoadFn)(JNIEnv*, jclass, jstring, jobject, jclass);

static jstring hooked_nativeLoad(JNIEnv* env, jclass runtimeClass,
                                  jstring filename, jobject classLoader, jclass caller) {
    if (caller == nullptr) {
        LOGI("Runtime.nativeLoad intercepted with null caller — fixing");

        // Strategy 1: Derive a class from the classLoader
        if (classLoader != nullptr) {
            // Try ClassLoader.loadClass("java.lang.Object") to get a valid Class
            jclass clsLoaderClass = env->GetObjectClass(classLoader);
            if (clsLoaderClass != nullptr) {
                jmethodID loadClassMethod = env->GetMethodID(
                    clsLoaderClass, "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;");
                if (loadClassMethod != nullptr) {
                    jstring objClassName = env->NewStringUTF("java.lang.Object");
                    if (objClassName != nullptr) {
                        // Clear any pending exception before calling loadClass
                        if (env->ExceptionCheck()) env->ExceptionClear();

                        jobject loadedClass = env->CallObjectMethod(
                            classLoader, loadClassMethod, objClassName);
                        env->DeleteLocalRef(objClassName);

                        if (env->ExceptionCheck()) {
                            env->ExceptionClear();
                        } else if (loadedClass != nullptr) {
                            caller = static_cast<jclass>(loadedClass);
                            LOGI("Runtime.nativeLoad: fixed null caller via classLoader → java.lang.Object");
                        }
                    }
                }
                env->DeleteLocalRef(clsLoaderClass);
            }
        }

        // Strategy 2: Fallback — use java.lang.Runtime itself as the caller
        if (caller == nullptr) {
            caller = runtimeClass;
            LOGI("Runtime.nativeLoad: fixed null caller → java.lang.Runtime (fallback)");
        }
    }

    // Call original implementation
    if (g_orig_nativeLoad_fn != nullptr) {
        jstring result = ((NativeLoadFn)g_orig_nativeLoad_fn)(
            env, runtimeClass, filename, classLoader, caller);
        // The load may have brought new libraries into the process
        // (e.g. a packer shell's libDexHelper.so via System.loadLibrary
        // in the guest Application's attach). Patch their GOTs now —
        // before any of their JNI methods get invoked.
        patch_newly_loaded_libraries();
        return result;
    }

    // If we somehow don't have the original, try dlsym as last resort
    LOGE("Runtime.nativeLoad: no original function pointer — cannot forward call");
    return nullptr;
}

/**
 * Install the Runtime.nativeLoad hook using RegisterNatives.
 *
 * Approach:
 * 1. Find java.lang.Runtime class
 * 2. Save original nativeLoad function pointer via GetMethodID + JNI internal lookup
 * 3. Register our hooked version via RegisterNatives
 */
static bool installNativeLoadHook(JNIEnv* env) {
    // Find java.lang.Runtime
    jclass runtimeClass = env->FindClass("java/lang/Runtime");
    if (runtimeClass == nullptr) {
        LOGE("installNativeLoadHook: cannot find java/lang/Runtime");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }

    // Try to get the original native function pointer from libart.so
    // The symbol name varies by ART version but we try the common ones
    void* libart = dlopen("libart.so", RTLD_NOLOAD);
    if (libart == nullptr) {
        LOGW("installNativeLoadHook: libart.so not found via RTLD_NOLOAD, trying dlopen");
        libart = dlopen("libart.so", RTLD_NOW);
    }

    if (libart != nullptr) {
        // ART internal symbol for Runtime_nativeLoad (static JNI method)
        // Try multiple symbol names as it varies across Android versions
        const char* symbols[] = {
            "_ZN3artL18Runtime_nativeLoadEP7_JNIEnvP7_jclassP8_jstringP8_jobjectS5_",
            "Runtime_nativeLoad",
            nullptr
        };

        for (int i = 0; symbols[i] != nullptr; i++) {
            g_orig_nativeLoad_fn = dlsym(libart, symbols[i]);
            if (g_orig_nativeLoad_fn != nullptr) {
                LOGI("installNativeLoadHook: found original at symbol '%s'", symbols[i]);
                break;
            }
        }
    }

    if (g_orig_nativeLoad_fn == nullptr) {
        // Fallback: use env->GetMethodID to verify the method exists,
        // then rely on RegisterNatives to stash the original internally.
        // We'll use a JNI trick: register, then we ARE the native now.
        // To call original, we need the old function pointer.
        // Without it, we try a different approach — call doLoad on Runtime directly.

        // Try using JNI GetStaticMethodID to verify method exists
        jmethodID nativeLoadMethod = env->GetStaticMethodID(
            runtimeClass, "nativeLoad",
            "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;");
        if (nativeLoadMethod == nullptr) {
            LOGE("installNativeLoadHook: Runtime.nativeLoad method not found");
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(runtimeClass);
            return false;
        }

        // Without the original symbol, we can still hook but won't be able to forward.
        // Use a wrapper approach: save the method ID and call via JNI CallStatic
        // But this would recursively call our hook... So we MUST have the original.
        LOGE("installNativeLoadHook: cannot find original native symbol in libart.so");
        env->DeleteLocalRef(runtimeClass);
        return false;
    }

    // Register our hooked version
    JNINativeMethod methods[] = {
        {
            const_cast<char*>("nativeLoad"),
            const_cast<char*>("(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;"),
            reinterpret_cast<void*>(hooked_nativeLoad)
        }
    };

    jint result = env->RegisterNatives(runtimeClass, methods, 1);
    env->DeleteLocalRef(runtimeClass);

    if (result != JNI_OK) {
        LOGE("installNativeLoadHook: RegisterNatives failed with code %d", result);
        g_orig_nativeLoad_fn = nullptr;
        return false;
    }

    LOGI("installNativeLoadHook: SUCCESS — Runtime.nativeLoad hooked via RegisterNatives");
    return true;
}

/**
 * JNI bridge for NativeHookBridge.nativeInstallRuntimeLoadHook()
 */
JNIEXPORT jboolean JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeInstallRuntimeLoadHook(
    JNIEnv* env, jobject thiz)
{
    (void)thiz;
    return installNativeLoadHook(env) ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
