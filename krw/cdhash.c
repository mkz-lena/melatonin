#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "melatonin.h"

#define MH_MAGIC_64   0xfeedfacfU
#define FAT_MAGIC     0xcafebabeU
#define FAT_MAGIC_64  0xcafebabfU
#define LC_CODE_SIGNATURE 0x1dU

#define CSSLOT_CODEDIRECTORY 0
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CSMAGIC_CODEDIRECTORY      0xfade0c02U

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0 || n > (long)(1 << 30)) { fclose(f); return NULL; }

    uint8_t *b = malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }

    fclose(f);
    *len = (size_t)n;
    return b;
}

/* first slice of a thin or fat image, NULL if not mach-o */
static const uint8_t *slice(const uint8_t *d, size_t len, size_t *avail) {
    if (len < 8) return NULL;

    uint32_t mbe = be32(d);
    if (mbe == FAT_MAGIC || mbe == FAT_MAGIC_64) {
        uint32_t n = be32(d + 4);
        if (!n) return NULL;

        const uint8_t *a = d + 8;
        size_t off = (mbe == FAT_MAGIC_64)
                   ? (size_t)(((uint64_t)be32(a + 8) << 32) | be32(a + 12))
                   : (size_t)be32(a + 8);
        if (off >= len) return NULL;

        *avail = len - off;
        return d + off;
    }

    if (le32(d) != MH_MAGIC_64) return NULL;
    *avail = len;
    return d;
}

/* hash the embedded CodeDirectory exactly like the kernel does; returns 0 on
   success, non-zero when the image carries no usable signature */
static int signed_cdhash(const uint8_t *img, size_t avail, uint8_t out[20]) {
    if (avail < 32) return -1;

    uint32_t ncmds = le32(img + 16);
    size_t cur = 32;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cur + 8 > avail) return -1;

        uint32_t cmd = le32(img + cur);
        uint32_t sz  = le32(img + cur + 4);
        if (sz < 8 || cur + sz > avail) return -1;

        if (cmd != LC_CODE_SIGNATURE) { cur += sz; continue; }

        uint32_t dataoff = le32(img + cur + 8);
        uint32_t datasize = le32(img + cur + 12);
        if (dataoff > avail || datasize > avail - dataoff) return -1;

        const uint8_t *sb = img + dataoff;
        uint32_t sbmagic = be32(sb);
        uint32_t sbcount = be32(sb + 8);

        if ((sbmagic != CSMAGIC_EMBEDDED_SIGNATURE && sbmagic != 0xfade0c01U) ||
            sbcount > 64)
            return -1;

        for (uint32_t k = 0; k < sbcount; k++) {
            const uint8_t *e = sb + 12 + k * 8;
            if ((size_t)(e - img) + 8 > avail) return -1;

            uint32_t type = be32(e);
            uint32_t off  = be32(e + 4);
            if (type != CSSLOT_CODEDIRECTORY) continue;
            if (off > datasize || (size_t)off + 40 > datasize) return -1;

            const uint8_t *cd = sb + off;
            uint32_t cdmagic = be32(cd);
            uint32_t cdlen   = be32(cd + 4);
            uint8_t  hashType = cd[37];

            if (cdmagic != CSMAGIC_CODEDIRECTORY) return -1;
            if (cdlen < 40 || (size_t)off + cdlen > datasize) return -1;

            if (hashType == 1) {          /* sha1 */
                mela_sha1(cd, cdlen, out);
                return 0;
            }
            if (hashType == 2 || hashType == 3) {   /* sha256 / truncated */
                uint8_t full[32];
                mela_sha256(cd, cdlen, full);
                memcpy(out, full, 20);
                return 0;
            }
            return -1;
        }
        return -1;
    }
    return -1;
}

void mela_cdhash_mem(const void *data, size_t len, uint8_t out[20]) {
    size_t avail = 0;
    const uint8_t *img = slice(data, len, &avail);

    if (img && signed_cdhash(img, avail, out) == 0) return;

    /* unsigned image: whole-file sha256, truncated */
    uint8_t full[32];
    mela_sha256(data, len, full);
    memcpy(out, full, 20);
}

int mela_cdhash_file(const char *path, uint8_t out[20]) {
    size_t len = 0;
    uint8_t *d = slurp(path, &len);
    if (!d) return -1;

    mela_cdhash_mem(d, len, out);
    free(d);
    return 0;
}

int mela_trust_add_file(const char *path) {
    uint8_t cd[20];
    if (mela_cdhash_file(path, cd) != 0) return -1;
    return mela_trust_add(cd);
}

static int is_macho(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    uint8_t m[4];
    int ok = fread(m, 1, sizeof m, f) == sizeof m;
    fclose(f);
    if (!ok) return 0;

    uint32_t be = be32(m), le = le32(m);
    return be == FAT_MAGIC || be == FAT_MAGIC_64 || le == MH_MAGIC_64;
}

int mela_trust_add_bundle(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;

    int added = 0;
    struct dirent *de;
    char path[1024];

    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (snprintf(path, sizeof path, "%s/%s", dir, de->d_name) >= (int)sizeof path)
            continue;

        struct stat st;
        if (lstat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            int n = mela_trust_add_bundle(path);
            if (n > 0) added += n;
        } else if (S_ISREG(st.st_mode) && is_macho(path)) {
            if (mela_trust_add_file(path) == 0) added++;
        }
    }

    closedir(d);
    return added;
}
