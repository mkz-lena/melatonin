#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * kdiff - compare two kernelcache images and report what changed.
 *
 * this is the 1-day side of the workflow: apple ships 27.0.1, then 27.2 with a
 * bulletin naming components. the bulletin says "out-of-bounds write in
 * AVEVideoEncoder, fixed by improved bounds checking". the diff says which
 * bytes, in which kext, so the check can be read instead of guessed.
 *
 * a whole-image diff of two kernelcaches is noisy: kexts move, sizes change,
 * and the compiler is not stable across builds. so the useful mode is
 *
 *   kdiff --kext com.apple.driver.AppleAVE2 --map old.map --map-new new.map \
 *         old.kc new.kc
 *
 * which pulls just that kext out of each image, using the __PRELINK_INFO map
 * from tools/prelink_map.py, and diffs those two windows. inside one kext the
 * layout is stable and only the patched functions show up.
 *
 * method: 16-byte content blocks, hash index over the new window, longest
 * forward runs as anchors, everything between anchors is a change region.
 * blocks that repeat are treated as ambiguous and never anchor, so padding and
 * duplicated stubs do not fake a match. no disassembler, no symbols required.
 */

#define MH_MAGIC_64   0xfeedfacfU
#define FAT_MAGIC     0xcafebabeU
#define FAT_MAGIC_64  0xcafebabfU
#define LC_SEGMENT_64 0x19U
#define LC_SYMTAB     0x2U

#define BLOCK 16u
#define MAX_SEGS 64
#define MAX_SYMS 200000

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

struct sym { const char *name; uint64_t value; };

struct image {
    uint8_t *data;
    size_t len;
    uint64_t kbase;
    int nseg;
    struct seg64 seg[MAX_SEGS];
    int nsym;
    struct sym *sym;
};

struct region {
    uint64_t old_va, new_va;
    uint64_t old_len, new_len;
    uint64_t same;
    const char *label;
};

/* --- aarch64 guard shapes ------------------------------------------------
 * "improved bounds checking" is an added compare plus an unsigned
 * conditional branch in front of a copy or an index. aarch64 is fixed width,
 * so a linear scan finds those without a disassembler. this is a ranking
 * signal, not a verdict: it says "read this region first", and the bytes say
 * what the check actually is.
 */
struct gcount { int insn, cmp, ubr, csel, cbz, ret, bl; };

static void guard_scan(const uint8_t *p, uint64_t len, struct gcount *g) {
    memset(g, 0, sizeof *g);
    if (!p) return;
    for (uint64_t off = 0; off + 4 <= len; off += 4) {
        uint32_t w;
        memcpy(&w, p + off, 4);
        g->insn++;
        /* cmp xN, #imm / cmp xN, xM */
        if (((w & 0xFFC00000u) == 0xF1000000u ||
             (w & 0xFF200000u) == 0xEB000000u) && (w & 0x1Fu) == 31u)
            g->cmp++;
        /* b.hs / b.lo / b.hi / b.ls */
        if ((w & 0xFF000010u) == 0x54000000u) {
            unsigned c = w & 0xFu;
            if (c == 2u || c == 3u || c == 8u || c == 9u) g->ubr++;
        }
        /* csel / csinc: clamp instead of branch */
        if ((w & 0x7FE00C00u) == 0x1A800000u ||
            (w & 0x7FE00C00u) == 0x1A800400u)
            g->csel++;
        if ((w & 0x7E000000u) == 0x34000000u) g->cbz++;
        if ((w & 0xFC000000u) == 0x94000000u) g->bl++;
        if (w == 0xD65F03C0u) g->ret++;
    }
}

static int guard_gain(const struct gcount *o, const struct gcount *n) {
    return (n->ubr - o->ubr) * 2 + (n->cmp - o->cmp) + (n->csel - o->csel);
}

/* regions that fall in a data segment decode like code often enough to fill
   the ranking with noise. only scan executable segments. */
static int va_in_code(const struct image *im, uint64_t va) {
    for (int i = 0; i < im->nseg; i++) {
        const struct seg64 *s = &im->seg[i];
        if (!s->filesize || va < s->vmaddr || va - s->vmaddr >= s->filesize)
            continue;
        if (!strcmp(s->segname, "__TEXT_EXEC") ||
            !strcmp(s->segname, "__TEXT") ||
            !strcmp(s->segname, "__PRELINK_TEXT") ||
            !strcmp(s->segname, "__TEXT_BOOT_EXEC"))
            return 1;
    }
    return 0;
}

struct guardhit {
    const char *kext;
    char seg[17];
    uint64_t old_va, new_va, old_len, new_len;
    struct gcount o, n;
};

struct kmap { uint64_t addr, size; char *name; };
static struct kmap *g_old_map, *g_new_map;
static size_t g_nold, g_nnew;

static int map_cmp(const void *a, const void *b) {
    const struct kmap *x = a, *y = b;
    return x->addr < y->addr ? -1 : x->addr > y->addr ? 1 : 0;
}

static int load_map(const char *path, struct kmap **out, size_t *n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    size_t cap = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long long a, s;
        char name[400];
        if (line[0] == '#') continue;
        if (sscanf(line, "%llx %llx %399s", &a, &s, name) != 3) continue;
        if (*n == cap) {
            cap = cap ? cap * 2 : 256;
            struct kmap *nr = realloc(*out, cap * sizeof **out);
            if (!nr) { fclose(f); return -1; }
            *out = nr;
        }
        (*out)[*n].addr = a;
        (*out)[*n].size = s;
        (*out)[*n].name = strdup(name);
        (*n)++;
    }
    fclose(f);
    if (*n) qsort(*out, *n, sizeof **out, map_cmp);
    return *n ? 0 : -1;
}

static const struct kmap *map_find(const struct kmap *m, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++)
        if (!strcmp(m[i].name, name)) return &m[i];
    return NULL;
}

static const char *map_for(const struct kmap *m, size_t n, uint64_t va, uint64_t *delta) {
    if (!n) return NULL;
    size_t lo = 0, hi = n;
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (m[mid].addr <= va) lo = mid; else hi = mid;
    }
    if (va < m[lo].addr || va - m[lo].addr >= m[lo].size) return NULL;
    if (delta) *delta = va - m[lo].addr;
    return m[lo].name;
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint8_t *read_all(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    if ((unsigned long)n > (1UL << 31)) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)n);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    fclose(f);
    if (b) *len = (size_t)n;
    return b;
}

static size_t slice_off(const uint8_t *d, size_t len) {
    if (len < 8) return (size_t)-1;
    uint32_t mbe = be32(d);
    if (mbe == FAT_MAGIC || mbe == FAT_MAGIC_64) {
        uint32_t n = be32(d + 4);
        size_t esz = (mbe == FAT_MAGIC_64) ? 32 : 20;
        if (n > 64 || 8 + n * esz > len) return (size_t)-1;
        for (uint32_t i = 0; i < n; i++) {
            const uint8_t *a = d + 8 + i * esz;
            uint64_t off = (esz == 32)
                ? ((uint64_t)be32(a + 8) << 32 | be32(a + 12))
                : be32(a + 8);
            if (off + 8 <= len) return (size_t)off;
        }
        return (size_t)-1;
    }
    return (((const struct mh64 *)d)->magic == MH_MAGIC_64) ? 0 : (size_t)-1;
}

static int load_image(const char *path, struct image *im) {
    memset(im, 0, sizeof *im);
    im->data = read_all(path, &im->len);
    if (!im->data) { fprintf(stderr, "kdiff: cannot read %s\n", path); return -1; }

    size_t off = slice_off(im->data, im->len);
    if (off == (size_t)-1) { fprintf(stderr, "kdiff: %s is not mach-o\n", path); return -1; }
    const uint8_t *img = im->data + off;
    size_t avail = im->len - off;
    if (avail < sizeof(struct mh64)) return -1;

    const struct mh64 *mh = (const struct mh64 *)img;
    if (mh->magic != MH_MAGIC_64) return -1;

    uint64_t symoff = 0, stroff = 0, nsyms = 0, strsize = 0;
    uint64_t cur = sizeof(struct mh64);

    for (uint32_t i = 0; i < mh->ncmds && i < 4096; i++) {
        if (cur + 8 > avail) break;
        const struct lc_any { uint32_t cmd, cmdsize; } *lc =
            (const struct lc_any *)(img + cur);
        if (lc->cmdsize < 8 || cur + lc->cmdsize > avail) break;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct seg64 *sg = (const struct seg64 *)(img + cur);
            if (sg->cmdsize >= sizeof *sg) {
                if (!im->kbase && !strncmp(sg->segname, "__TEXT", 16))
                    im->kbase = sg->vmaddr;
                if (im->nseg < MAX_SEGS) im->seg[im->nseg++] = *sg;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            const struct symtab_cmd *st = (const struct symtab_cmd *)(img + cur);
            symoff = st->symoff; nsyms = st->nsyms;
            stroff = st->stroff; strsize = st->strsize;
        }
        cur += lc->cmdsize;
    }

    if (nsyms && nsyms < MAX_SYMS &&
        symoff + nsyms * sizeof(struct nl64) <= avail &&
        stroff + strsize <= avail) {
        im->sym = calloc((size_t)nsyms, sizeof *im->sym);
        if (im->sym) {
            for (uint64_t i = 0; i < nsyms; i++) {
                const struct nl64 *nl = (const struct nl64 *)(img + symoff + i * sizeof *nl);
                if (nl->n_strx >= strsize || !nl->n_value) continue;
                const char *nm = (const char *)(img + stroff + nl->n_strx);
                if (!memchr(nm, 0, strsize - nl->n_strx)) continue;
                im->sym[im->nsym].name = nm;
                im->sym[im->nsym].value = nl->n_value;
                im->nsym++;
            }
        }
    }
    return 0;
}

/* virtual address -> bytes in the file, or NULL when not file-backed */
static const uint8_t *va_bytes(const struct image *im, uint64_t va) {
    for (int i = 0; i < im->nseg; i++) {
        const struct seg64 *sg = &im->seg[i];
        if (!sg->filesize || va < sg->vmaddr) continue;
        uint64_t d = va - sg->vmaddr;
        if (d >= sg->filesize) continue;
        uint64_t f = sg->fileoff + d;
        if (f >= im->len) continue;
        return im->data + f;
    }
    return NULL;
}

static uint64_t hash16(const uint8_t *p) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 16; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

struct hidx { uint64_t *key; int32_t *val; uint32_t mask; };

static void hidx_free(struct hidx *h) { free(h->key); free(h->val); }

static int hidx_build(struct hidx *h, const uint8_t *p, uint32_t nblocks) {
    uint32_t cap = 16;
    while (cap < nblocks * 2 + 16) cap <<= 1;
    h->mask = cap - 1;
    h->key = calloc(cap, sizeof *h->key);
    h->val = malloc(cap * sizeof *h->val);
    if (!h->key || !h->val) return -1;
    for (uint32_t i = 0; i < cap; i++) h->val[i] = -1;

    for (uint32_t i = 0; i < nblocks; i++) {
        uint64_t k = hash16(p + (size_t)i * BLOCK);
        if (!k) k = 1;
        uint32_t s = (uint32_t)k & h->mask;
        for (uint32_t probe = 0; probe < 8; probe++) {
            uint32_t at = (s + probe) & h->mask;
            if (h->val[at] == -1) { h->key[at] = k; h->val[at] = (int32_t)i; break; }
            if (h->key[at] == k) { h->val[at] = -2; break; }   /* repeated: never anchor */
        }
    }
    return 0;
}

static int32_t hidx_find(const struct hidx *h, uint64_t k) {
    if (!k) k = 1;
    uint32_t s = (uint32_t)k & h->mask;
    for (uint32_t probe = 0; probe < 8; probe++) {
        uint32_t at = (s + probe) & h->mask;
        if (h->val[at] == -1) return -1;
        if (h->key[at] == k) return h->val[at] == -2 ? -1 : h->val[at];
    }
    return -1;
}

static const char *sym_for(const struct image *im, uint64_t va, uint64_t *delta) {
    const char *best = NULL;
    uint64_t bd = 0;
    for (int i = 0; i < im->nsym; i++) {
        uint64_t v = im->sym[i].value;
        if (v > va) continue;
        uint64_t d = va - v;
        if (d > 0x20000) continue;
        if (!best || d < bd) { best = im->sym[i].name; bd = d; }
    }
    if (best && delta) *delta = bd;
    return best;
}

static void print_hex(const uint8_t *p, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) printf("%02x", p[i]);
}

struct acc {
    struct region *regs;
    size_t n, cap;
    uint64_t old_bytes, new_bytes, same_bytes;
};

static int acc_push(struct acc *a, struct region r) {
    if (a->n == a->cap) {
        size_t nc = a->cap ? a->cap * 2 : 64;
        struct region *nr = realloc(a->regs, nc * sizeof *nr);
        if (!nr) return -1;
        a->regs = nr;
        a->cap = nc;
    }
    a->regs[a->n] = r;
    if (r.label) a->regs[a->n].label = strdup(r.label);
    a->n++;
    a->old_bytes += r.old_len;
    a->new_bytes += r.new_len;
    a->same_bytes += r.same;
    return 0;
}

static void acc_free(struct acc *a) {
    for (size_t i = 0; i < a->n; i++) free((void *)a->regs[i].label);
    free(a->regs);
    a->regs = NULL;
    a->n = a->cap = 0;
}

/* diff two byte windows that correspond to each other */
static int diff_span(const uint8_t *pa, uint64_t vm_a, size_t len_a,
                     const uint8_t *pb, uint64_t vm_b, size_t len_b,
                     long min_anchor, const char *label, struct acc *acc)
{
    uint32_t ba = (uint32_t)(len_a / BLOCK);
    uint32_t bb = (uint32_t)(len_b / BLOCK);
    if (!ba || !bb) return 0;

    struct hidx h;
    if (hidx_build(&h, pb, bb)) return -1;

    int32_t *pair = malloc((size_t)ba * sizeof *pair);
    if (!pair) { hidx_free(&h); return -1; }
    for (uint32_t i = 0; i < ba; i++) {
        uint64_t k = hash16(pa + (size_t)i * BLOCK);
        int32_t j = hidx_find(&h, k);
        if (j >= 0 && memcmp(pa + (size_t)i * BLOCK, pb + (size_t)j * BLOCK, BLOCK))
            j = -1;
        pair[i] = j;
    }

    uint32_t i = 0, prev_a = 0, prev_b = 0;

    while (i < ba) {
        if (pair[i] < 0) { i++; continue; }

        uint32_t run = 1;
        while (i + run < ba && pair[i + run] == pair[i] + (int32_t)run) run++;

        if ((long)run >= min_anchor) {
            uint32_t a0 = i, b0 = (uint32_t)pair[i];

            if (a0 >= prev_a && b0 >= prev_b && (a0 > prev_a || b0 > prev_b)) {
                struct region r;
                r.old_va = vm_a + (uint64_t)prev_a * BLOCK;
                r.new_va = vm_b + (uint64_t)prev_b * BLOCK;
                r.old_len = (uint64_t)(a0 - prev_a) * BLOCK;
                r.new_len = (uint64_t)(b0 - prev_b) * BLOCK;
                r.same = 0;
                r.label = label;

                uint64_t lim = r.old_len < r.new_len ? r.old_len : r.new_len;
                const uint8_t *x = pa + (size_t)prev_a * BLOCK;
                const uint8_t *y = pb + (size_t)prev_b * BLOCK;
                while (r.same < lim && x[r.same] == y[r.same]) r.same++;

                if (acc_push(acc, r)) { free(pair); hidx_free(&h); return -1; }
            }

            acc->same_bytes += (uint64_t)run * BLOCK;
            if (a0 + run > prev_a) prev_a = a0 + run;
            if (b0 + run > prev_b) prev_b = b0 + run;
            i = a0 + run;
        } else {
            i++;
        }
    }

    if (prev_a > ba) prev_a = ba;
    if (prev_b > bb) prev_b = bb;
    if (ba > prev_a || bb > prev_b) {
        struct region r;
        r.old_va = vm_a + (uint64_t)prev_a * BLOCK;
        r.new_va = vm_b + (uint64_t)prev_b * BLOCK;
        r.old_len = (uint64_t)(ba - prev_a) * BLOCK;
        r.new_len = (uint64_t)(bb - prev_b) * BLOCK;
        r.same = 0;
        r.label = label;
        uint64_t lim = r.old_len < r.new_len ? r.old_len : r.new_len;
        const uint8_t *x = pa + (size_t)prev_a * BLOCK;
        const uint8_t *y = pb + (size_t)prev_b * BLOCK;
        while (r.same < lim && x[r.same] == y[r.same]) r.same++;
        if (acc_push(acc, r)) { free(pair); hidx_free(&h); return -1; }
    }

    free(pair);
    hidx_free(&h);
    return 0;
}

static int find_seg_nth(const struct image *im, const char *name, int nth, struct seg64 *out) {
    for (int i = 0; i < im->nseg; i++) {
        if (strcmp(im->seg[i].segname, name) || !im->seg[i].filesize) continue;
        if (nth-- == 0) { *out = im->seg[i]; return 1; }
    }
    return 0;
}

/* a prelinked kext starts with its own mach header; pull its segment table so
   each piece (__TEXT_EXEC, __DATA_CONST, ...) can be diffed separately */
static int embedded_segments(const struct image *im, uint64_t va,
                             struct seg64 *out, int max, int *nout) {
    const uint8_t *h = va_bytes(im, va);
    if (!h) return -1;
    const struct mh64 *mh = (const struct mh64 *)h;
    if (mh->magic != MH_MAGIC_64) return -1;

    /* stay inside the containing segment */
    size_t room = 0;
    for (int i = 0; i < im->nseg; i++) {
        const struct seg64 *sg = &im->seg[i];
        if (sg->filesize && va >= sg->vmaddr && va - sg->vmaddr < sg->filesize)
            room = sg->filesize - (size_t)(va - sg->vmaddr);
    }

    int n = 0;
    uint64_t cur = sizeof(struct mh64);
    for (uint32_t i = 0; i < mh->ncmds && i < 512; i++) {
        if (cur + 8 > room) break;
        const struct lc_any { uint32_t cmd, cmdsize; } *lc =
            (const struct lc_any *)(h + cur);
        if (lc->cmdsize < 8 || cur + lc->cmdsize > room) break;
        if (lc->cmd == LC_SEGMENT_64 && n < max) {
            const struct seg64 *sg = (const struct seg64 *)(h + cur);
            if (sg->cmdsize >= sizeof *sg) out[n++] = *sg;
        }
        cur += lc->cmdsize;
    }
    *nout = n;
    return n ? 0 : -1;
}

static int seg_ordinal(const struct image *im, int si) {
    int n = 0;
    for (int i = 0; i < si; i++)
        if (!strcmp(im->seg[i].segname, im->seg[si].segname)) n++;
    return n;
}

static int seg_span(const struct image *im, const struct seg64 *sg, size_t *off, size_t *n) {
    if (!sg->filesize || sg->fileoff >= im->len) return 0;
    uint64_t end = sg->fileoff + sg->filesize;
    if (end > im->len) end = im->len;
    if (end <= sg->fileoff) return 0;
    *off = (size_t)sg->fileoff;
    *n = (size_t)(end - sg->fileoff);
    return 1;
}

/* diff one kext's embedded segments into acc. returns 0 ok, -1 unusable. */
static int diff_one_kext(const struct image *a, const struct image *b,
                         const struct kmap *ka, const struct kmap *kb,
                         long min_anchor, struct acc *acc)
{
    struct seg64 sa[16], sb[16];
    int na = 0, nb = 0;
    if (embedded_segments(a, ka->addr, sa, 16, &na) ||
        embedded_segments(b, kb->addr, sb, 16, &nb))
        return -1;

    for (int i = 0; i < na; i++) {
        const struct seg64 *qa = &sa[i];
        const struct seg64 *qb = NULL;

        /* __LINKEDIT is shared by every prelinked kext and points outside the
           kext's own load range. diffing it in every kext makes the numbers
           meaningless, so only take segments that live inside the kext. */
        if (qa->vmaddr < ka->addr || qa->filesize > ka->size ||
            qa->vmaddr - ka->addr > ka->size - qa->filesize)
            continue;

        for (int j = 0; j < nb; j++)
            if (!strcmp(sb[j].segname, qa->segname)) qb = &sb[j];
        if (!qb || !qa->filesize || !qb->filesize) continue;

        const uint8_t *p = va_bytes(a, qa->vmaddr);
        const uint8_t *q = va_bytes(b, qb->vmaddr);
        if (!p || !q) continue;

        char label[256];
        snprintf(label, sizeof label, "%s:%.16s", ka->name, qa->segname);
        size_t la = qa->filesize, lb = qb->filesize;
        if (la > (1u << 28)) la = 1u << 28;
        if (lb > (1u << 28)) lb = 1u << 28;
        if (diff_span(p, qa->vmaddr, la, q, qb->vmaddr, lb,
                      min_anchor, label, acc)) return -1;
    }
    return 0;
}

struct kstat {
    const char *name;
    uint64_t old_size, new_size;
    uint64_t ch_old, ch_new;
    size_t regions;
};

static int kstat_cmp(const void *x, const void *y) {
    const struct kstat *a = x, *b = y;
    /* least relative change first: a security fix in a stable kext is a
       handful of instructions, and sorts above a rewritten one */
    uint64_t ra = a->old_size ? a->ch_old * 1000000 / a->old_size : 0;
    uint64_t rb = b->old_size ? b->ch_old * 1000000 / b->old_size : 0;
    if (ra != rb) return ra < rb ? -1 : 1;
    return a->ch_old < b->ch_old ? -1 : a->ch_old > b->ch_old ? 1 : 0;
}

int main(int argc, char **argv) {
    const char *pa = NULL, *pb = NULL;
    const char *mapfile = NULL, *mapfile_new = NULL, *kext = NULL;
    long min_anchor = 4, top = 40, show_bytes = 32;
    int json = 0, segs = 0, all_kexts = 0, guards = 0;
    const char *match = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--min") && i + 1 < argc) min_anchor = strtol(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--top") && i + 1 < argc) top = strtol(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--bytes") && i + 1 < argc) show_bytes = strtol(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--map") && i + 1 < argc) mapfile = argv[++i];
        else if (!strcmp(argv[i], "--map-new") && i + 1 < argc) mapfile_new = argv[++i];
        else if (!strcmp(argv[i], "--kext") && i + 1 < argc) kext = argv[++i];
        else if (!strcmp(argv[i], "--kexts")) all_kexts = 1;
        else if (!strcmp(argv[i], "--segs")) segs = 1;
        else if (!strcmp(argv[i], "--guards")) guards = 1;
        else if (!strcmp(argv[i], "--match") && i + 1 < argc) match = argv[++i];
        else if (!strcmp(argv[i], "--json")) json = 1;
        else if (!pa) pa = argv[i];
        else pb = argv[i];
    }
    if (!pa) {
        fprintf(stderr,
            "usage: kdiff <old.kc> <new.kc> [--kext id] [--map old.map] [--map-new new.map]\n"
            "              [--segs] [--min blocks] [--top n] [--bytes n] [--json]\n"
            "              [--guards] [--match substr]\n");
        return 2;
    }
    if (!pb) pb = pa;
    if (mapfile && !mapfile_new) mapfile_new = mapfile;

    if (mapfile && (load_map(mapfile, &g_old_map, &g_nold) ||
                    load_map(mapfile_new, &g_new_map, &g_nnew))) {
        fprintf(stderr, "kdiff: cannot read map\n");
        return 1;
    }

    struct image a, b;
    if (load_image(pa, &a) || load_image(pb, &b)) return 1;

    if (segs) {
        for (int pass = 0; pass < 2; pass++) {
            struct image *im = pass ? &b : &a;
            printf("%s kbase 0x%llx\n", pass ? pb : pa, (unsigned long long)im->kbase);
            for (int i = 0; i < im->nseg; i++)
                printf("  %-18s va=0x%-12llx size=%8llu off=0x%llx\n",
                       im->seg[i].segname, (unsigned long long)im->seg[i].vmaddr,
                       (unsigned long long)im->seg[i].filesize,
                       (unsigned long long)im->seg[i].fileoff);
        }
        return 0;
    }

    struct acc acc;
    memset(&acc, 0, sizeof acc);

    if (all_kexts) {
        if (!g_nold || !g_nnew) {
            fprintf(stderr, "kdiff: --kexts needs --map and --map-new\n");
            return 2;
        }
        struct kstat *ks = NULL;
        size_t nk = 0, kcap = 0;
        struct guardhit *hits = NULL;
        size_t nh = 0, hcap = 0;

        for (size_t i = 0; i < g_nold; i++) {
            const struct kmap *ka = &g_old_map[i];
            const struct kmap *kb = map_find(g_new_map, g_nnew, ka->name);
            if (!kb || ka->size < 8192) continue;
            if (match && !strstr(ka->name, match)) continue;

            struct acc one;
            memset(&one, 0, sizeof one);
            if (diff_one_kext(&a, &b, ka, kb, min_anchor, &one)) {
                acc_free(&one);
                continue;
            }
            if (!one.n) { acc_free(&one); continue; }

            if (guards) {
                for (size_t r = 0; r < one.n; r++) {
                    struct region *g = &one.regs[r];
                    struct gcount go, gn;
                    guard_scan(va_bytes(&a, g->old_va), g->old_len, &go);
                    guard_scan(va_bytes(&b, g->new_va), g->new_len, &gn);
                    if (gn.insn < 8 || guard_gain(&go, &gn) < 2) continue;
                    if (!va_in_code(&b, g->new_va)) continue;
                    /* a patch adds a few instructions, it does not move the
                       whole segment. huge growth is layout, not a guard. */
                    if (g->new_len > g->old_len + 512 ||
                        g->old_len > g->new_len + 512) continue;
                    if (nh == hcap) {
                        hcap = hcap ? hcap * 2 : 64;
                        struct guardhit *nhr = realloc(hits, hcap * sizeof *nhr);
                        if (!nhr) break;
                        hits = nhr;
                    }
                    struct guardhit h;
                    memset(&h, 0, sizeof h);
                    const char *seg = g->label ? strrchr(g->label, ':') : NULL;
                    snprintf(h.seg, sizeof h.seg, "%.16s", seg ? seg + 1 : "-");
                    h.kext = ka->name;
                    h.old_va = g->old_va; h.new_va = g->new_va;
                    h.old_len = g->old_len; h.new_len = g->new_len;
                    h.o = go; h.n = gn;
                    hits[nh++] = h;
                }
            }

            if (nk == kcap) {
                kcap = kcap ? kcap * 2 : 64;
                struct kstat *nr = realloc(ks, kcap * sizeof *nr);
                if (!nr) { acc_free(&one); return 1; }
                ks = nr;
            }
            ks[nk].name = ka->name;
            ks[nk].old_size = ka->size;
            ks[nk].new_size = kb->size;
            ks[nk].ch_old = one.old_bytes;
            ks[nk].ch_new = one.new_bytes;
            ks[nk].regions = one.n;
            nk++;
            acc_free(&one);
        }

        qsort(ks, nk, sizeof *ks, kstat_cmp);
        size_t klim = (size_t)top < nk ? (size_t)top : nk;

        if (json) {
            printf("{\"old\":\"%s\",\"new\":\"%s\",\"kexts\":[", pa, pb);
            for (size_t i = 0; i < klim; i++)
                printf("%s{\"kext\":\"%s\",\"old_size\":%llu,\"new_size\":%llu,"
                       "\"changed_old\":%llu,\"changed_new\":%llu,\"regions\":%zu}",
                       i ? "," : "", ks[i].name,
                       (unsigned long long)ks[i].old_size,
                       (unsigned long long)ks[i].new_size,
                       (unsigned long long)ks[i].ch_old,
                       (unsigned long long)ks[i].ch_new, ks[i].regions);
            printf("],\"guards\":[");
            for (size_t i = 0; i < nh; i++)
                printf("%s{\"kext\":\"%s\",\"old_va\":\"0x%llx\","
                       "\"new_va\":\"0x%llx\",\"old_len\":%llu,\"new_len\":%llu,"
                       "\"cmp_old\":%d,\"cmp_new\":%d,"
                       "\"ubr_old\":%d,\"ubr_new\":%d,"
                       "\"csel_old\":%d,\"csel_new\":%d}",
                       i ? "," : "", hits[i].kext,
                       (unsigned long long)hits[i].old_va,
                       (unsigned long long)hits[i].new_va,
                       (unsigned long long)hits[i].old_len,
                       (unsigned long long)hits[i].new_len,
                       hits[i].o.cmp, hits[i].n.cmp,
                       hits[i].o.ubr, hits[i].n.ubr,
                       hits[i].o.csel, hits[i].n.csel);
            printf("]}\n");
        } else {
            printf("old %s\nnew %s\n", pa, pb);
            printf("%zu kexts changed; least relative change first\n\n", nk);
            printf("%-56s %10s %10s %7s %7s\n",
                   "kext", "size", "changed", "new", "regions");
            for (size_t i = 0; i < klim; i++)
                printf("%-56s %10llu %10llu %7llu %7zu\n",
                       ks[i].name,
                       (unsigned long long)ks[i].old_size,
                       (unsigned long long)ks[i].ch_old,
                       (unsigned long long)ks[i].ch_new,
                       ks[i].regions);

            if (guards) {
                /* code-shaped hits first: a region with a ret or a bl is a
                   function, one without is probably a table that decoded. */
                for (size_t i = 0; i < nh; i++)
                    for (size_t j = i + 1; j < nh; j++) {
                        int ci = hits[i].n.ret || hits[i].n.bl;
                        int cj = hits[j].n.ret || hits[j].n.bl;
                        int gi = guard_gain(&hits[i].o, &hits[i].n) + ci * 1000;
                        int gj = guard_gain(&hits[j].o, &hits[j].n) + cj * 1000;
                        if (gj > gi) {
                            struct guardhit t = hits[i];
                            hits[i] = hits[j];
                            hits[j] = t;
                        }
                    }
                printf("\n%zu guard-shaped regions (compare / unsigned branch / "
                       "csel gained)\n\n", nh);
                printf("%-44s %-13s %11s %11s %s\n",
                       "kext", "segment", "cmp", "ubr", "old_va");
                for (size_t i = 0; i < nh; i++) {
                    printf("%-44s %-13.13s %4d->%-4d %4d->%-4d 0x%llx  %s\n",
                           hits[i].kext, hits[i].seg,
                           hits[i].o.cmp, hits[i].n.cmp,
                           hits[i].o.ubr, hits[i].n.ubr,
                           (unsigned long long)hits[i].old_va,
                           hits[i].n.ret || hits[i].n.bl ? "code" : "data?");
                }
            }
        }
        free(hits);
        free(ks);
        acc_free(&acc);
        free(a.data); free(a.sym);
        free(b.data); free(b.sym);
        for (size_t i = 0; i < g_nold; i++) free(g_old_map[i].name);
        for (size_t i = 0; i < g_nnew; i++) free(g_new_map[i].name);
        free(g_old_map); free(g_new_map);
        return 0;
    }

    if (kext) {
        const struct kmap *ka = map_find(g_old_map, g_nold, kext);
        const struct kmap *kb = map_find(g_new_map, g_nnew, kext);
        if (!ka || !kb) {
            fprintf(stderr, "kdiff: kext %s not in %s map\n", kext, ka ? "new" : "old");
            return 1;
        }
        if (diff_one_kext(&a, &b, ka, kb, min_anchor, &acc)) {
            fprintf(stderr, "kdiff: %s has no embedded mach header at 0x%llx\n",
                    kext, (unsigned long long)ka->addr);
            return 1;
        }
    } else {
        for (int si = 0; si < a.nseg; si++) {
            const struct seg64 *sa = &a.seg[si];
            struct seg64 sb;
            if (!find_seg_nth(&b, sa->segname, seg_ordinal(&a, si), &sb)) continue;

            size_t oa, na, ob, nb;
            if (!seg_span(&a, sa, &oa, &na)) continue;
            if (!seg_span(&b, &sb, &ob, &nb)) continue;
            if (na > (1u << 29) || nb > (1u << 29)) continue;

            if (diff_span(a.data + oa, sa->vmaddr, na,
                          b.data + ob, sb.vmaddr, nb, min_anchor, NULL, &acc)) return 1;
        }
    }

    /* biggest first, or most guard-shaped first when --guards is on */
    int *gain = NULL;
    if (guards) {
        gain = calloc(acc.n ? acc.n : 1, sizeof *gain);
        for (size_t i = 0; i < acc.n; i++) {
            struct gcount go, gn;
            guard_scan(va_bytes(&a, acc.regs[i].old_va), acc.regs[i].old_len, &go);
            guard_scan(va_bytes(&b, acc.regs[i].new_va), acc.regs[i].new_len, &gn);
            int gg = guard_gain(&go, &gn);
            if (acc.regs[i].new_len >= 128 && !gn.ret && !gn.bl) gg -= 1000;
            if (!va_in_code(&b, acc.regs[i].new_va)) gg = 0;
            if (acc.regs[i].new_len > acc.regs[i].old_len + 512 ||
                acc.regs[i].old_len > acc.regs[i].new_len + 512) gg = 0;
            gain[i] = gn.insn >= 8 ? gg : 0;
        }
    }
    for (size_t i = 0; i < acc.n; i++)
        for (size_t j = i + 1; j < acc.n; j++) {
            int better;
            if (guards)
                better = gain[j] != gain[i]
                    ? gain[j] > gain[i]
                    : acc.regs[j].old_len + acc.regs[j].new_len >
                      acc.regs[i].old_len + acc.regs[i].new_len;
            else
                better = acc.regs[j].old_len + acc.regs[j].new_len >
                         acc.regs[i].old_len + acc.regs[i].new_len;
            if (better) {
                struct region t = acc.regs[i];
                acc.regs[i] = acc.regs[j];
                acc.regs[j] = t;
                if (gain) { int g = gain[i]; gain[i] = gain[j]; gain[j] = g; }
            }
        }

    size_t lim = (size_t)top < acc.n ? (size_t)top : acc.n;

    if (json) {
        printf("{\"old\":\"%s\",\"new\":\"%s\",\"kbase_old\":\"0x%llx\","
               "\"kbase_new\":\"0x%llx\",\"regions\":%zu,"
               "\"changed_old\":%llu,\"changed_new\":%llu,\"identical\":%llu,"
               "\"detail\":[",
               pa, pb, (unsigned long long)a.kbase, (unsigned long long)b.kbase,
               acc.n, (unsigned long long)acc.old_bytes,
               (unsigned long long)acc.new_bytes, (unsigned long long)acc.same_bytes);

        for (size_t i = 0; i < lim; i++) {
            uint64_t d = 0;
            const char *nm = sym_for(&a, acc.regs[i].old_va, &d);
            const char *kx = acc.regs[i].label;
            uint64_t kd = acc.regs[i].old_va - (kx ? acc.regs[i].old_va : 0);
            if (!kx) kx = map_for(g_old_map, g_nold, acc.regs[i].old_va, &kd);
            else kd = 0;

            printf("%s{\"old_va\":\"0x%llx\",\"new_va\":\"0x%llx\","
                   "\"old_len\":%llu,\"new_len\":%llu,\"symbol\":",
                   i ? "," : "", (unsigned long long)acc.regs[i].old_va,
                   (unsigned long long)acc.regs[i].new_va,
                   (unsigned long long)acc.regs[i].old_len,
                   (unsigned long long)acc.regs[i].new_len);
            if (nm) printf("\"%s\",\"sym_delta\":%llu", nm, (unsigned long long)d);
            else printf("null,\"sym_delta\":0");
            printf(",\"kext\":");
            if (kx) printf("\"%s\",\"kext_delta\":%llu", kx, (unsigned long long)kd);
            else printf("null,\"kext_delta\":0");
            printf("}");
        }
        printf("]}\n");
    } else {
        printf("old %s  kbase 0x%llx\n", pa, (unsigned long long)a.kbase);
        printf("new %s  kbase 0x%llx\n", pb, (unsigned long long)b.kbase);
        if (kext) printf("kext %s\n", kext);
        printf("changed old %llu bytes, new %llu bytes, identical %llu bytes in %zu regions\n",
               (unsigned long long)acc.old_bytes, (unsigned long long)acc.new_bytes,
               (unsigned long long)acc.same_bytes, acc.n);

        for (size_t i = 0; i < lim; i++) {
            uint64_t d = 0;
            const char *nm = sym_for(&a, acc.regs[i].old_va, &d);
            const char *kx = acc.regs[i].label;
            uint64_t kd = 0;
            if (!kx) kx = map_for(g_old_map, g_nold, acc.regs[i].old_va, &kd);

            printf("\n[%zu] old 0x%llx +%llu -> new 0x%llx +%llu",
                   i + 1, (unsigned long long)acc.regs[i].old_va,
                   (unsigned long long)acc.regs[i].old_len,
                   (unsigned long long)acc.regs[i].new_va,
                   (unsigned long long)acc.regs[i].new_len);
            if (nm) printf("  %s+0x%llx", nm, (unsigned long long)d);
            if (kx && !kext) printf("  [%s +0x%llx]", kx, (unsigned long long)kd);
            printf("\n");

            if (guards) {
                struct gcount go, gn;
                guard_scan(va_bytes(&a, acc.regs[i].old_va),
                           acc.regs[i].old_len, &go);
                guard_scan(va_bytes(&b, acc.regs[i].new_va),
                           acc.regs[i].new_len, &gn);
                printf("    cmp %d->%d  ubr %d->%d  csel %d->%d%s\n",
                       go.cmp, gn.cmp, go.ubr, gn.ubr, go.csel, gn.csel,
                       gn.insn >= 8 && gain[i] >= 2
                           ? (!gn.ret && !gn.bl
                              ? "  guard? (no ret/bl: may be data)"
                              : "  GUARD")
                           : "");
            }

            if (show_bytes > 0) {
                uint64_t n2 = (uint64_t)show_bytes;
                if (n2 > acc.regs[i].old_len) n2 = acc.regs[i].old_len;
                const uint8_t *p = va_bytes(&a, acc.regs[i].old_va);
                printf("    old ");
                if (p) print_hex(p, n2); else printf("(not file-backed)");
                printf("\n");

                n2 = (uint64_t)show_bytes;
                if (n2 > acc.regs[i].new_len) n2 = acc.regs[i].new_len;
                const uint8_t *q = va_bytes(&b, acc.regs[i].new_va);
                printf("    new ");
                if (q) print_hex(q, n2); else printf("(not file-backed)");
                printf("\n");
            }
        }
    }

    int changed = acc.n ? 1 : 0;
    free(gain);
    acc_free(&acc);
    free(a.data); free(a.sym);
    free(b.data); free(b.sym);
    for (size_t i = 0; i < g_nold; i++) free(g_old_map[i].name);
    for (size_t i = 0; i < g_nnew; i++) free(g_new_map[i].name);
    free(g_old_map); free(g_new_map);
    return changed;   /* like diff(1): 0 same, 1 different */
}
