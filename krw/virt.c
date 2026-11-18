#include <string.h>
#include "melatonin.h"

/*
 * arm64e translation walk, 16K granule, 4 levels.
 * level L entry shift = 14 + 11*(3-L):  L0=47 L1=36 L2=25 L3=14
 * block at level L covers 2^(14 + 11*(3-L)) bytes.
 */

static inline uint64_t lvl_idx(kva_t va, int lvl) {
    return (va >> (14 + 11 * (3 - lvl))) & 0x7FF;
}

static inline uint64_t lvl_size(int lvl) {
    return 1ULL << (14 + 11 * (3 - lvl));
}

static inline uint64_t desc_phys(uint64_t d) {
    return d & 0x0000FFFFFFFFC000ULL;
}

int mela_leaf_va(kva_t va, uint64_t *pa) {
    const mela_phys_ops *p = mela_phys();
    if (!p || !pa) return -1;

    uint64_t table = desc_phys(p->ttbr1);

    for (int lvl = 0; lvl <= 2; lvl++) {
        uint64_t d = 0;
        if (p->read(table + lvl_idx(va, lvl) * 8, &d, 8) != 0) return -1;
        if (!(d & 1)) return -1;                 /* invalid */

        if (!(d & 2)) {                          /* block mapping */
            uint64_t sz = lvl_size(lvl);
            uint64_t base = d & ~(sz - 1) & 0x0000FFFFFFFFFFFFULL;
            *pa = base | (va & (sz - 1));
            return 0;
        }
        table = desc_phys(d);
        if (!table) return -1;
    }

    uint64_t d = 0;
    if (p->read(table + lvl_idx(va, 3) * 8, &d, 8) != 0) return -1;
    if (!(d & 1)) return -1;

    *pa = desc_phys(d) | (va & MELA_PAGE_MASK);
    return 0;
}

static int transfer(kva_t va, void *buf, size_t len, int is_write) {
    const mela_phys_ops *p = mela_phys();
    if (!p) return -1;

    uint8_t *b = (uint8_t *)buf;
    while (len) {
        uint64_t pa = 0;
        if (mela_leaf_va(va, &pa) != 0) return -1;

        size_t n = MELA_PAGE_SIZE - (va & MELA_PAGE_MASK);
        if (n > len) n = len;

        int rc = is_write ? p->write(pa, b, n) : p->read(pa, b, n);
        if (rc != 0) return -1;

        va += n;
        b  += n;
        len -= n;
    }
    return 0;
}

int mela_virt_read(kva_t va, void *buf, size_t len) {
    return transfer(va, buf, len, 0);
}

int mela_virt_write(kva_t va, const void *buf, size_t len) {
    return transfer(va, (void *)buf, len, 1);
}
