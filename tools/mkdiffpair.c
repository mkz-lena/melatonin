#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * mkdiffpair - emit two kernelcache-shaped images for tools/kdiff tests.
 *
 * the code segment is deterministic pseudo-random content with the block index
 * mixed into every 16-byte block, so identical blocks are unique and the diff
 * has unambiguous anchors. the "new" image patches three blocks and grows by
 * 0x40 bytes, which is the shape of a real one-day: a bound check added, a
 * function slightly longer, everything else byte-identical.
 */

#define MH_MAGIC_64   0xfeedfacfU
#define LC_SEGMENT_64 0x19U
#define LC_SYMTAB     0x2U
#define KBASE         0xFFFFFFF007004000ULL
#define TEXT_EXEC_VA  (KBASE + 0x00100000ULL)
#define CODE_SIZE     0x10000u
#define GROW          0x40u

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
struct nl64 { uint32_t n_strx; uint8_t n_type, n_sect; uint16_t n_desc; uint64_t n_value; };

struct symdef { const char *name; uint32_t code_off; };

static const struct symdef syms[] = {
    { "_test_sym_a", 0x1000 },
    { "_test_sym_b", 0x4000 },
    { "_test_sym_c", 0x9000 },
};
#define NSYMS ((uint32_t)(sizeof syms / sizeof syms[0]))

static void gen_code(uint8_t *p, uint32_t n) {
    for (uint32_t b = 0; b < n / 16; b++) {
        uint32_t x = b * 2654435761u + 0x9e3779b9u;
        for (int k = 0; k < 4; k++) {
            x = x * 1664525u + 1013904223u;
            memcpy(p + b * 16 + k * 4, &x, 4);
        }
    }
}

static int emit(const char *path, int mutate) {
    uint32_t code_len = CODE_SIZE + (mutate ? GROW : 0);
    uint32_t hdr = sizeof(struct mh64) + 2 * sizeof(struct seg64) + sizeof(struct symtab_cmd);
    uint32_t symoff = hdr;
    uint32_t stroff = symoff + NSYMS * sizeof(struct nl64);
    uint32_t strsize = 0;
    for (uint32_t i = 0; i < NSYMS; i++) strsize += (uint32_t)strlen(syms[i].name) + 1;

    uint32_t code_off = (stroff + strsize + 0x3fff) & ~0x3fffu;
    uint32_t filesize = code_off + code_len;

    struct mh64 mh = {
        .magic = MH_MAGIC_64, .cputype = 0x0100000c, .cpusubtype = 2,
        .filetype = 0x0b, .ncmds = 3,
        .sizeofcmds = 2 * sizeof(struct seg64) + sizeof(struct symtab_cmd),
    };

    struct seg64 text;
    memset(&text, 0, sizeof text);
    text.cmd = LC_SEGMENT_64;
    text.cmdsize = sizeof text;
    strcpy(text.segname, "__TEXT");
    text.vmaddr = KBASE;
    text.vmsize = 0x100000;
    text.fileoff = 0;
    text.filesize = hdr;
    text.maxprot = 7; text.initprot = 5;

    struct seg64 exec;
    memset(&exec, 0, sizeof exec);
    exec.cmd = LC_SEGMENT_64;
    exec.cmdsize = sizeof exec;
    strcpy(exec.segname, "__TEXT_EXEC");
    exec.vmaddr = TEXT_EXEC_VA;
    exec.vmsize = (code_len + 0x3fff) & ~0x3fffu;
    exec.fileoff = code_off;
    exec.filesize = code_len;
    exec.maxprot = 7; exec.initprot = 5;

    struct symtab_cmd st = {
        .cmd = LC_SYMTAB, .cmdsize = sizeof st,
        .symoff = symoff, .nsyms = NSYMS,
        .stroff = stroff, .strsize = strsize,
    };

    struct nl64 nl[NSYMS];
    memset(nl, 0, sizeof nl);
    uint32_t sx = 0;
    char *strs = calloc(1, strsize);
    if (!strs) return 1;
    for (uint32_t i = 0; i < NSYMS; i++) {
        nl[i].n_strx = sx;
        nl[i].n_type = 0x0f;            /* N_SECT | N_EXT */
        nl[i].n_sect = 2;
        nl[i].n_value = TEXT_EXEC_VA + syms[i].code_off;
        memcpy(strs + sx, syms[i].name, strlen(syms[i].name) + 1);
        sx += (uint32_t)strlen(syms[i].name) + 1;
    }

    uint8_t *code = malloc(code_len);
    if (!code) { free(strs); return 1; }
    gen_code(code, CODE_SIZE);

    if (mutate) {
        /* the "bound check": three sites change, one of them grows by 8 bytes
           by shifting everything after it. this mirrors a patched prologue. */
        memset(code + 0x1000, 0x1f, 8);   /* e.g. cmp w8, #0 ; b.lo */
        memset(code + 0x1004, 0x20, 4);
        memset(code + 0x4000, 0x1f, 16);
        memset(code + 0x9000, 0xd5, 4);   /* e.g. a nop replacing a call */

        uint8_t tail[GROW];
        memset(tail, 0xaa, sizeof tail);
        memmove(code + 0x9040 + GROW, code + 0x9040, CODE_SIZE - 0x9040);
        memcpy(code + 0x9040, tail, sizeof tail);
    }

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); free(code); free(strs); return 1; }
    int ok = 1;
    ok &= fwrite(&mh, sizeof mh, 1, f) == 1;
    ok &= fwrite(&text, sizeof text, 1, f) == 1;
    ok &= fwrite(&exec, sizeof exec, 1, f) == 1;
    ok &= fwrite(&st, sizeof st, 1, f) == 1;
    ok &= fwrite(nl, sizeof nl, 1, f) == 1;
    ok &= fwrite(strs, 1, strsize, f) == strsize;
    ok &= fseek(f, (long)code_off, SEEK_SET) == 0;
    ok &= fwrite(code, 1, code_len, f) == code_len;
    fclose(f);

    free(code);
    free(strs);
    (void)filesize;
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *a = argc > 1 ? argv[1] : "old.kc";
    const char *b = argc > 2 ? argv[2] : "new.kc";
    if (emit(a, 0)) return 1;
    if (emit(b, 1)) return 1;
    printf("mkdiffpair: %s (clean) / %s (3 patches, +0x%x bytes)\n", a, b, GROW);
    return 0;
}
