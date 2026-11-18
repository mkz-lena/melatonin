#include "melatonin.h"
#include "exploit.h"

/*
 * Boot provider contract.
 *
 * A platform module fills a mela_phys_ops and hands it to mela_phys_register()
 * before mela_primitive_init() runs. The ops must expose:
 *   - read/write over physical addresses, at least 8-byte granular
 *   - ttbr1: TTBR1_EL1 for the current task
 *   - phys_base: physmap base used to derive DRAM addresses
 *
 * The provider also fills g_mela.kbase and g_mela.kslide before returning.
 * Replace the weak stub below at link time with a real provider object.
 */
__attribute__((weak))
int mela_boot_provider(mela_phys_ops *out) {
    (void)out;
    return -1;
}

int mela_primitive_init(void) {
    if (mela_krw_ready()) return 0;
    return mela_exploit_run();
}
