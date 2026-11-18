#ifndef MELA_OFFSETS_H
#define MELA_OFFSETS_H
#include <stdint.h>

/* iPhone16e A18 ios 27.x arm64e.
 * kbase offsets: allproc, rootvnode, apfs_mnt, pac_key
 * struct offsets: every proc_*, task_*, ucred_*, label_* field
 */
#define OFF_KERNEL_BASE 0xFFFFFFF007004000ULL

struct mela_offsets {
    uint32_t kern_version;

    /* kbase-relative */
    uint64_t allproc;
    uint64_t rootvnode;
    uint64_t apfs_mnt;
    uint64_t pac_key;

    /* proc fields */
    uint64_t proc_list;
    uint64_t proc_pid;
    uint64_t proc_ro;
    uint64_t proc_task;
    uint64_t proc_ucred;      /* inside proc_ro */

    /* ucred fields */
    uint64_t ucred_uid;
    uint64_t ucred_ruid;
    uint64_t ucred_svuid;
    uint64_t ucred_label;

    /* label fields */
    uint64_t label_sandbox;

    /* trust cache */
    uint64_t trust_head;
    uint64_t tc_count;
    uint64_t tc_entries;
    uint64_t tc_entry_size;
    uint64_t tc_hash;
    uint64_t tc_flags;

    /* proc fields (cont) */
    uint64_t proc_comm;

    /* task fields */
    uint64_t task_itk;        /* itk_self */
    uint64_t ipc_port_kobject;

    /* mount field */
    uint64_t mount_flags;

    /* amfi / cs */
    uint64_t cs_enforcement_disable;
    uint64_t pe_i_can_has_debugger;
    uint64_t amfi_check_dyld_policy;
};

extern struct mela_offsets g_off;

int  mela_offsets_probe(void);
int  mela_offsets_autoprobe(void);
void mela_offsets_seed(void);

#endif
