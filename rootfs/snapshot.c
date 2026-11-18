#include "melatonin.h"
#include "offsets.h"
#include "snapshot.h"

static uint64_t mnt_ptr(void) {
    return kread64(kaddr(g_off.apfs_mnt));
}

static uint64_t apfs_of(uint64_t mnt) {
    if (!mela_is_kptr(mnt)) return 0;
    uint64_t apfs = kread64(mnt + APFS_MNT_APFS);
    return apfs ? mela_canon(apfs) : mnt;
}

uint64_t find_ssv_snapshot(void) {
    uint64_t mnt = mnt_ptr();
    uint64_t apfs = apfs_of(mnt);
    if (!apfs) return 0;

    uint64_t snap = kread64(apfs + APFS_APFS_ROOT);
    int guard = 0;

    while (snap && guard++ < 0x1000) {
        uint64_t cur  = mela_canon(snap);
        uint64_t name = kread64(cur + APFS_SNAP_NAME);

        /* "com.apple.os.update" LE, first eight bytes */
        if (name == 0x6C7070612E6D6F63ULL) return cur;

        uint64_t next = kread64(cur + APFS_SNAP_NEXT);
        if (!next) break;
        snap = next;
    }
    return 0;
}

/* point root_info back at the live dev and clear the snapshot bit */
int snapshot_select_live(void) {
    uint64_t mnt  = mnt_ptr();
    uint64_t apfs = apfs_of(mnt);
    if (!apfs) return -1;

    uint64_t live = kread64(apfs + APFS_SB_ROOTDEV);
    if (!live) return -1;

    /* already switched: keep the flag clear and report success */
    if (kread64(apfs + APFS_APFS_ROOT) == live) {
        uint64_t fl = kread64(mnt + g_off.mount_flags);
        fl &= ~MELA_MNT_SNAPSHOT;
        kwrite64(mnt + g_off.mount_flags, fl);
        g_mela.ssv_off = true;
        return 0;
    }

    if (!find_ssv_snapshot()) return -1;

    if (kwrite64(apfs + APFS_APFS_ROOT, live) != 0) return -1;

    uint64_t flags = kread64(mnt + g_off.mount_flags);
    flags &= ~MELA_MNT_SNAPSHOT;
    if (kwrite64(mnt + g_off.mount_flags, flags) != 0) return -1;

    g_mela.ssv_off = true;
    return 0;
}
