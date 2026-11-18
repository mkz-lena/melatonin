#include "melatonin.h"

/* read a field, canonicalise, optionally follow depth indirections */
kva_t kread_ptr(kva_t addr, int depth) {
    uint64_t raw = kread64(addr);
    if (!raw) return 0;
    if (!mela_is_kptr(raw)) return mela_strip(raw);

    kva_t va = mela_canon(raw);
    for (int i = 0; i < depth; i++) {
        kva_t nxt = kread64(va);
        if (!mela_is_kptr(nxt)) break;
        va = mela_canon(nxt);
    }
    return va;
}
