#include <sys/mount.h>
#include <errno.h>
#include "melatonin.h"
#include "offsets.h"
#include "snapshot.h"

int rootfs_remount(void) {
    uint64_t mnt = kread64(kaddr(g_off.apfs_mnt));
    if (!mela_is_kptr(mnt)) return -1;

    uint64_t flags = kread64(mnt + g_off.mount_flags);
    flags &= ~MELA_MNT_RDONLY;
    if (kwrite64(mnt + g_off.mount_flags, flags) != 0) return -1;

    uint64_t rootv = kread64(kaddr(g_off.rootvnode));
    if (mela_is_kptr(rootv)) {
        uint64_t vflags = kread64(mela_canon(rootv) + 0x78);
        vflags &= ~(1ULL << 0);          /* VROOT clear of readonly */
        kwrite64(mela_canon(rootv) + 0x78, vflags);
    }

    if (mount("apfs", "/", MNT_UPDATE, NULL) != 0) {
        return errno ? -errno : -1;
    }

    g_mela.rootful = true;
    return 0;
}
