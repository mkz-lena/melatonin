#ifndef MELA_SNAPSHOT_H
#define MELA_SNAPSHOT_H

#include "melatonin.h"

/* apfs_mount_t / snap layout (arm64e, 16K) */
#define APFS_MNT_APFS    0x18ULL
#define APFS_APFS_ROOT   0x38ULL
#define APFS_SNAP_NEXT   0x08ULL
#define APFS_SNAP_NAME   0x40ULL
#define APFS_SB_ROOTDEV  0x10ULL

#define MELA_MNT_RDONLY    (1ULL << 0)
#define MELA_MNT_SNAPSHOT  (1ULL << 3)

int      snapshot_select_live(void);
uint64_t find_ssv_snapshot(void);
int      rootfs_remount(void);
int      resign_tree(const char *root);

#endif
