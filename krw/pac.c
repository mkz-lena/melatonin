#include "melatonin.h"

#define VA_LOW_MASK 0x0000000FFFFFFFFFULL
#define VA_TOP      0xFFFFFFF000000000ULL

uint64_t mela_strip(uint64_t p) { return p & VA_LOW_MASK; }

uint64_t mela_canon(uint64_t p) { return (p & VA_LOW_MASK) | VA_TOP; }

int mela_is_kptr(uint64_t p) {
    if (!p) return 0;
    uint64_t v = mela_canon(p);
    return v >= MELA_KERN_MIN && v < MELA_KERN_MAX;
}

/* rebuild a signed kernel pointer: key[63:60] ctx[47:61] */
uint64_t mela_rebind(uint64_t p, uint64_t key, uint64_t ctx) {
    uint64_t out = p & VA_LOW_MASK;
    out |= (ctx & 0x3FFFULL) << 48;
    out |= (key & 0xFULL) << 60;
    return out | VA_TOP;
}
