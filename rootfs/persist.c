#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <spawn.h>
#include <sys/wait.h>
#include "melatonin.h"

extern char **environ;

static const char *prefix(void) {
    const char *r = getenv("MELA_SIM_ROOT");
    return r ? r : "";
}

static int mkdir_p(const char *path) {
    char buf[512];
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

static const char *kPlist =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""
" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
"<plist version=\"1.0\"><dict>\n"
"  <key>Label</key><string>com.melatonin.app</string>\n"
"  <key>ProgramArguments</key><array>\n"
"    <string>/var/jb/usr/libexec/melatonind</string>\n"
"    <string>--daemon</string>\n"
"  </array>\n"
"  <key>RunAtLoad</key><true/>\n"
"  <key>KeepAlive</key><true/>\n"
"</dict></plist>\n";

int mela_persist_install(void) {
    char dir[512], path[512];

    if (snprintf(dir, sizeof dir, "%s/Library/LaunchDaemons", prefix()) <= 0) return -1;
    if (mkdir_p(dir) != 0) return -2;

    if (snprintf(path, sizeof path, "%s/com.melatonin.app.plist", dir) <= 0) return -3;

    FILE *f = fopen(path, "w");
    if (!f) return -4;
    fputs(kPlist, f);
    fclose(f);

#if defined(__APPLE__)
    char *boot[] = { "/bin/launchctl", "bootstrap", "system", path, NULL };
    char *enab[] = { "/bin/launchctl", "enable", "system/com.melatonin.app", NULL };
    pid_t pid;
    int st;

    if (posix_spawn(&pid, "/bin/launchctl", NULL, NULL, boot, environ) == 0)
        waitpid(pid, &st, 0);
    if (posix_spawn(&pid, "/bin/launchctl", NULL, NULL, enab, environ) == 0)
        waitpid(pid, &st, 0);
#endif

    return 0;
}
