#include <stdio.h>
#include <unistd.h>
#include "melatonin.h"
#include "offsets.h"

#define ST_PROC     (1u << 0)
#define ST_CRED     (1u << 1)
#define ST_SANDBOX  (1u << 2)
#define ST_KPROC    (1u << 3)
#define ST_PORT     (1u << 4)
#define ST_MOUNT    (1u << 5)
#define ST_CS       (1u << 6)
#define ST_DEBUG    (1u << 7)
#define ST_POLICY   (1u << 8)

uint32_t mela_selftest(int print) {
    uint32_t bad = 0;
    kva_t self = proc_find(getpid());

    if (!self) {
        bad |= ST_PROC;
    } else {
        kva_t ro = kread64(self + g_off.proc_ro);
        kva_t cr = kread64(mela_canon(ro) + g_off.proc_ucred);
        cr = mela_canon(cr);

        if ((uint32_t)kread64(cr + g_off.ucred_uid) != 0) bad |= ST_CRED;

        kva_t lab = kread64(cr + g_off.ucred_label);
        if (lab && kread64(mela_canon(lab) + g_off.label_sandbox) != 0)
            bad |= ST_SANDBOX;

        kva_t st = kread64(self + g_off.proc_task);
        kva_t port = kread64(mela_canon(st) + g_off.task_itk);
        kva_t kp = proc_find(0);

        if (!kp) {
            bad |= ST_KPROC;
        } else {
            kva_t ktask = kread64(kp + g_off.proc_task);
            if (kread64(mela_canon(port) + g_off.ipc_port_kobject) != ktask)
                bad |= ST_PORT;
        }
    }

    kva_t mnt = kread64(kaddr(g_off.apfs_mnt));
    if (!mnt || (kread64(mela_canon(mnt) + g_off.mount_flags) & 1ULL))
        bad |= ST_MOUNT;

    if (mela_get32(kaddr(g_off.cs_enforcement_disable)) != 1) bad |= ST_CS;
    if (mela_get32(kaddr(g_off.pe_i_can_has_debugger)) != 0x52800020u) bad |= ST_DEBUG;
    if (mela_get32(kaddr(g_off.amfi_check_dyld_policy)) != 0x52800000u) bad |= ST_POLICY;

    if (print) printf("[selftest] %s (0x%x)\n", bad ? "fail" : "pass", bad);
    return bad;
}
