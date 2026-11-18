#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <spawn.h>
#include <sys/wait.h>
#include "melatonin.h"

extern char **environ;

static const char *prefix(void) {
    const char *r = getenv("MELA_SIM_ROOT");
    return r ? r : "";
}

static int run_ex(char *const av[], int quiet) {
    pid_t pid = 0;
    int st = 0;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_t *fap = NULL;

    if (quiet) {
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        fap = &fa;
    }

    int rc = posix_spawnp(&pid, av[0], fap, NULL, av, environ);
    if (quiet) posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) return -1;

    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int run(char *const av[]) { return run_ex(av, 0); }

static int mkdir_p(const char *path) {
    char buf[1024];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof buf) return -1;
    memcpy(buf, path, n + 1);

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && access(buf, F_OK) != 0) return -1;
        *p = '/';
    }
    if (mkdir(buf, 0755) != 0 && access(buf, F_OK) != 0) return -1;
    return 0;
}

static int sign_path(const char *path, const char *ldid) {
    char *av[] = { (char *)ldid, "-S", (char *)path, NULL };
    return run_ex(av, 1);
}

static void sign_execs(const char *dir, const char *ldid, int depth) {
    if (depth > 8 || !ldid) return;

    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *de;
    char path[1024];

    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (snprintf(path, sizeof path, "%s/%s", dir, de->d_name) >= (int)sizeof path)
            continue;

        struct stat st;
        if (lstat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            sign_execs(path, ldid, depth + 1);
        } else if (S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
            sign_path(path, ldid);
        }
    }

    closedir(d);
}

static const char *find_ldid(void) {
    static char buf[1024];
    const char *p = prefix();

    if (snprintf(buf, sizeof buf, "%s/var/jb/usr/bin/ldid", p) > 0 &&
        access(buf, X_OK) == 0)
        return buf;

    if (access("/usr/bin/ldid", X_OK) == 0) return "/usr/bin/ldid";
    if (access("/var/jb/usr/bin/ldid", X_OK) == 0) return "/var/jb/usr/bin/ldid";
    return NULL;
}

int mela_install_app(const char *src) {
    if (!src || !*src) return -1;

    const char *base = strrchr(src, '/');
    base = base ? base + 1 : src;

    size_t bl = strlen(base);
    if (bl < 5 || strcmp(base + bl - 4, ".app") != 0) return -2;

    char apps[1024], dest[1024];
    if (snprintf(apps, sizeof apps, "%s/Applications", prefix()) >= (int)sizeof apps)
        return -3;
    if (mkdir_p(apps) != 0) return -4;

    if (snprintf(dest, sizeof dest, "%s/%s", apps, base) >= (int)sizeof dest)
        return -5;

    char *rm[]  = { "rm", "-rf", dest, NULL };
    char *cp[]  = { "cp", "-a", (char *)src, dest, NULL };
    char *own[] = { "chown", "-R", "0:0", dest, NULL };
    char *mod[] = { "chmod", "-R", "755", dest, NULL };

    if (run(rm) != 0) return -6;
    if (run(cp) != 0) return -7;

    run_ex(own, 1);               /* ignored where not permitted */
    run_ex(mod, 1);
    const char *ldid = find_ldid();
    if (ldid) sign_execs(dest, ldid, 0);

    if (mela_krw_ready() && mela_trust_prepare() == 0)
        mela_trust_add_bundle(dest);

    char *uicache[] = { "uicache", "-a", NULL };
    run_ex(uicache, 1);           /* ignored when absent */
    char *killall[] = { "killall", "-9", "installd", NULL };
    run_ex(killall, 1);

    return 0;
}
