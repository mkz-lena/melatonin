#include "melatonin.h"
#include "offsets.h"

/* host-side stand-ins for the Darwin-only tail of the pipeline */

/* mirrors the kernel-side flag flip so the verifier sees real state */
int rootfs_remount(void) {
    kva_t mnt = kread64(kaddr(g_off.apfs_mnt));
    if (!mnt) return -1;

    uint64_t flags = kread64(mnt + g_off.mount_flags);
    flags &= ~1ULL;                    /* clear readonly */
    if (kwrite64(mnt + g_off.mount_flags, flags) != 0) return -1;

    g_mela.rootful = true;
    return 0;
}

int resign_tree(const char *root) { (void)root; return 0; }
