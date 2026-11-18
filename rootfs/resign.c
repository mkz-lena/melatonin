#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;

#define MH_MAGIC_64   0xfeedfacfUL
#define MH_CIGAM_64   0xcffaedfeUL
#define MH_MAGIC      0xfeedfaceUL
#define FAT_MAGIC     0xcafebabeUL

static int is_macho(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint32_t m = 0;
    if (fread(&m, sizeof m, 1, f) != 1) { fclose(f); return 0; }
    fclose(f);
    return m == MH_MAGIC_64 || m == MH_CIGAM_64 ||
           m == MH_MAGIC    || m == FAT_MAGIC;
}

static int sign_one(const char *path) {
    char *ldid = "/var/jb/usr/bin/ldid";
    if (access(ldid, X_OK) != 0) ldid = "/usr/bin/ldid";
    if (access(ldid, X_OK) != 0) {
        chmod(path, 0755);
        return 0;
    }

    char *argv[] = { ldid, "-S", (char *)path, NULL };
    pid_t pid = 0;
    int st = 0;
    if (posix_spawn(&pid, ldid, NULL, NULL, argv, environ) != 0) return -1;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int resign_walk(const char *dir, int depth) {
    if (depth > 6) return 0;

    DIR *d = opendir(dir);
    if (!d) return -1;

    struct dirent *e;
    char path[1024];
    int n = 0;

    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;

        int k = snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (k <= 0 || (size_t)k >= sizeof path) continue;

        struct stat sb;
        if (lstat(path, &sb) != 0) continue;

        if (S_ISDIR(sb.st_mode)) {
            if (resign_walk(path, depth + 1) == 0) n++;
        } else if (S_ISREG(sb.st_mode) && (sb.st_mode & 0111) && is_macho(path)) {
            if (sign_one(path) == 0) n++;
        }
    }

    closedir(d);
    return n;
}

int resign_tree(const char *root) {
    return resign_walk(root, 0);
}
