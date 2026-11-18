#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- minimal mach-o model (no host sdk needed) ---- */
#define MH_MAGIC_64  0xfeedfacfU
#define FAT_MAGIC    0xcafebabeU
#define FAT_MAGIC_64 0xcafebabfU
#define LC_SEGMENT_64 0x19U
#define LC_SYMTAB     0x2U

struct mh64 {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
};

struct seg64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};

struct symtab_cmd { uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize; };

struct nl64 {
    uint32_t n_strx;
    uint8_t  n_type, n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint8_t *read_all(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0 || n > (long)(1 << 30)) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)n);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    fclose(f);
    if (b) *len = (size_t)n;
    return b;
}

/* returns offset of the first arm64e slice inside data */
static size_t slice_off(const uint8_t *d, size_t len) {
    if (len < 8) return 0;
    uint32_t m = ((const struct mh64 *)d)->magic;
    uint32_t mbe = be32(d);

    if (mbe == FAT_MAGIC || mbe == FAT_MAGIC_64) {
        uint32_t n = be32(d + 4);
        size_t esz = (mbe == FAT_MAGIC_64) ? 32 : 20;
        for (uint32_t i = 0; i < n; i++) {
            const uint8_t *a = d + 8 + i * esz;
            uint64_t off = (esz == 32) ? ((uint64_t)be32(a + 8) << 32 | be32(a + 12))
                                       : be32(a + 8);
            if (off < len) return (size_t)off;
        }
        return 0;
    }
    return (m == MH_MAGIC_64) ? 0 : (size_t)-1;
}

static int want(const char *name, const char *sym) {
    if (!strcmp(name, sym)) return 1;
    if (name[0] == '_' && !strcmp(name + 1, sym)) return 1;
    return 0;
}

int main(int argc, char **argv) {
    const char *path = NULL, *mode = "table";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--emit") && i + 1 < argc) mode = argv[++i];
        else path = argv[i];
    }
    if (!path) {
        fprintf(stderr, "usage: koff <kernelcache> [--emit table|json|header]\n");
        return 2;
    }

    size_t len = 0;
    uint8_t *d = read_all(path, &len);
    if (!d) { fprintf(stderr, "koff: cannot read %s\n", path); return 1; }

    size_t off = slice_off(d, len);
    if (off == (size_t)-1 || off >= len) {
        fprintf(stderr, "koff: not a mach-o image\n");
        free(d);
        return 1;
    }
    const uint8_t *img = d + off;
    size_t avail = len - off;
    if (avail < sizeof(struct mh64)) { free(d); return 1; }

    const struct mh64 *mh = (const struct mh64 *)img;
    if (mh->magic != MH_MAGIC_64) { free(d); return 1; }

    uint64_t kbase = 0, symoff = 0, stroff = 0, nsyms = 0, strsize = 0;
    uint64_t cur = sizeof(struct mh64);

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cur + 8 > avail) break;
        const struct lc_any { uint32_t cmd, cmdsize; } *lc =
            (const struct lc_any *)(img + cur);
        if (lc->cmdsize < 8 || cur + lc->cmdsize > avail) break;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct seg64 *sg = (const struct seg64 *)(img + cur);
            if (!strncmp(sg->segname, "__TEXT", 16) && !kbase) kbase = sg->vmaddr;
        } else if (lc->cmd == LC_SYMTAB) {
            const struct symtab_cmd *st = (const struct symtab_cmd *)(img + cur);
            symoff = st->symoff; nsyms = st->nsyms;
            stroff = st->stroff; strsize = st->strsize;
        }
        cur += lc->cmdsize;
    }

    if (!kbase) { fprintf(stderr, "koff: no __TEXT\n"); free(d); return 1; }
    if (!nsyms || symoff + nsyms * sizeof(struct nl64) > avail ||
        stroff + strsize > avail) {
        fprintf(stderr, "koff: no usable symtab\n");
        free(d);
        return 1;
    }

    const char *names[] = { "allproc", "rootvnode", "apfs_mount", "cs_enforcement_disable" };
    const char *keys[]  = { "allproc", "rootvnode", "apfs_mnt",  "cs_enforcement_disable" };
    uint64_t vals[4] = {0};

    for (uint64_t i = 0; i < nsyms; i++) {
        const struct nl64 *nl = (const struct nl64 *)(img + symoff + i * sizeof *nl);
        if (nl->n_strx >= strsize) continue;
        const char *nm = (const char *)(img + stroff + nl->n_strx);
        if (!memchr(nm, 0, strsize - nl->n_strx)) continue;
        for (int k = 0; k < 4; k++)
            if (!vals[k] && want(nm, names[k]) && nl->n_value >= kbase)
                vals[k] = nl->n_value - kbase;
    }

    if (!strcmp(mode, "json")) {
        printf("{\"kbase\":\"0x%llx\",\"allproc\":\"0x%llx\","
               "\"rootvnode\":\"0x%llx\",\"apfs_mnt\":\"0x%llx\","
               "\"cs_enforcement_disable\":\"0x%llx\"}\n",
               (unsigned long long)kbase,
               (unsigned long long)vals[0], (unsigned long long)vals[1],
               (unsigned long long)vals[2], (unsigned long long)vals[3]);
    } else if (!strcmp(mode, "header")) {
        printf("/* generated from kernelcache */\n");
        printf("#define OFF_KERNEL_BASE 0x%llxULL\n", (unsigned long long)kbase);
        for (int k = 0; k < 4; k++)
            if (vals[k])
                printf("#define OFF_%s 0x%llxULL\n", keys[k],
                       (unsigned long long)vals[k]);
    } else {
        printf("kbase 0x%llx\n", (unsigned long long)kbase);
        for (int k = 0; k < 4; k++)
            printf("%-24s 0x%llx\n", keys[k], (unsigned long long)vals[k]);
    }

    free(d);
    return 0;
}
