#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "melatonin.h"
#include "offsets.h"

/* 4-byte access over the active backend */
static int put32(kva_t a, uint32_t v) { return kwrite(a, &v, sizeof v); }

static uint32_t get32(kva_t a) {
    uint32_t v = 0;
    kread(a, &v, sizeof v);
    return v;
}

/* mov w0, #imm  ; ret */
static int patch_fn(kva_t fn, uint32_t insn) {
    uint32_t buf[2] = { insn, 0xD65F03C0u };
    return kwrite(fn, buf, sizeof buf);
}

int mela_patch_return_true(kva_t fn)  { return patch_fn(fn, 0x52800020u); }
int mela_patch_return_false(kva_t fn) { return patch_fn(fn, 0x52800000u); }

uint32_t mela_get32(kva_t a) { return get32(a); }

int amfi_enable(void) {
    if (!mela_krw_ready()) return -1;

    kva_t cs = kaddr(g_off.cs_enforcement_disable);
    if (put32(cs, 1) != 0) return -2;

    if (mela_patch_return_true(kaddr(g_off.pe_i_can_has_debugger)) != 0) return -3;
    if (mela_patch_return_false(kaddr(g_off.amfi_check_dyld_policy)) != 0) return -4;

    return 0;
}

/* drop amfid so launchd respawns it with an empty entitlement cache */
int amfi_flush_cache(void) {
    if (!mela_krw_ready()) return -1;

    kva_t proc = proc_find_by_name("amfid");
    if (!proc) return 0;

#if defined(__APPLE__) && !defined(MELA_HOST_SIM)
    pid_t pid = (pid_t)kread64(proc + g_off.proc_pid);
    if (pid > 1) kill(pid, SIGKILL);
#endif
    return 1;
}
