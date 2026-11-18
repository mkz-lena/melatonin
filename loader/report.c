#include <stdio.h>
#include <unistd.h>
#include "melatonin.h"
#include "offsets.h"

/* runtime snapshot used on device bring-up: shows which backend attached,
   where the kernel landed, the live offset table and every state check */
int mela_report(void) {
    const mela_phys_ops *po = mela_phys();
    const mela_krw_ops  *ko = mela_krw();

    printf("[%s] %s %s  pid=%d\n", MELA_NAME, MELA_DOMAIN, MELA_VERSION, (int)getpid());
    printf("%-14s %s\n", "backend",
           po ? po->name : (ko ? ko->name : "(none)"));

    printf("%-14s 0x%llx\n", "kbase", (unsigned long long)g_mela.kbase);
    printf("%-14s 0x%llx\n", "kslide", (unsigned long long)g_mela.kslide);
    printf("%-14s %s\n", "rootful", g_mela.rootful ? "yes" : "no");
    printf("%-14s %s\n", "primed", g_mela.primed ? "yes" : "no");

    if (po) {
        printf("%-14s 0x%llx\n", "ttbr1", (unsigned long long)po->ttbr1);
        printf("%-14s 0x%llx\n", "phys_base", (unsigned long long)po->phys_base);
    }

    if (mela_krw_ready()) mela_offsets_report("runtime");

    printf("%-14s %llu (free slot %d)\n", "trust",
           (unsigned long long)mela_trust_count(), mela_trust_free_slot());
    printf("%-14s 0x%x\n", "selftest", mela_selftest(0));
    printf("%-14s %s\n", "exploit", mela_exploit_last());
    return 0;
}
