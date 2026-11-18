#include <string.h>
#include "melatonin.h"

/* ---------------------------------------------------------------- registry */

static const mela_krw_ops  *g_krw;
static const mela_phys_ops *g_phys;

int mela_krw_register(const mela_krw_ops *ops) {
    if (!ops || !ops->read64 || !ops->write64) return -1;
    if (ops->init && ops->init() != 0) return -2;
    g_krw = ops;
    return 0;
}

const mela_krw_ops *mela_krw(void) { return g_krw; }

int mela_phys_register(const mela_phys_ops *ops) {
    if (!ops || !ops->read || !ops->write || !ops->ttbr1) return -1;
    g_phys = ops;
    return 0;
}

const mela_phys_ops *mela_phys(void) { return g_phys; }

/* ------------------------------------------------------------- dispatchers */

uint64_t kread64(kva_t addr) {
    if (g_krw) return g_krw->read64(addr);
    uint64_t v = 0;
    if (mela_virt_read(addr, &v, sizeof v) != 0) return 0;
    return v;
}

int kwrite64(kva_t addr, uint64_t val) {
    if (g_krw) return g_krw->write64(addr, val);
    return mela_virt_write(addr, &val, sizeof val);
}

int kread(kva_t addr, void *buf, size_t len) {
    if (g_krw && g_krw->read) {
        if (g_krw->read(addr, buf, len) == 0) return 0;
    }
    return mela_virt_read(addr, buf, len);
}

int kwrite(kva_t addr, const void *buf, size_t len) {
    if (g_krw && g_krw->write) {
        if (g_krw->write(addr, buf, len) == 0) return 0;
    }
    return mela_virt_write(addr, buf, len);
}

/* ------------------------------------------------------------------ bringup */

int mela_krw_ready(void) { return g_krw != NULL || g_phys != NULL; }
