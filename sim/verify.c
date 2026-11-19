#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "melatonin.h"
#include "offsets.h"
#include "sim.h"

static int check(const char *name, int cond) {
    printf("[test] %-16s %s\n", name, cond ? "pass" : "FAIL");
    return cond;
}

static int hexeq(const uint8_t *b, size_t n, const char *hex) {
    static const char dig[] = "0123456789abcdef";
    if (strlen(hex) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        if (hex[i * 2]     != dig[b[i] >> 4]) return 0;
        if (hex[i * 2 + 1] != dig[b[i] & 15]) return 0;
    }
    return 1;
}

static int write_file(const char *path, const void *data, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fwrite(data, 1, n, f) == n;
    fclose(f);
    return ok ? 0 : -1;
}

int sim_verify(void) {
    int ok = 1;

    kva_t self = proc_find(getpid());
    ok &= check("self proc", self != 0);
    if (!self) return 1;

    kva_t ro   = kread64(self + g_off.proc_ro);
    kva_t cred = kread64(ro + g_off.proc_ucred);
    ok &= check("uid zero", (uint32_t)kread64(cred + g_off.ucred_uid) == 0);
    ok &= check("ruid zero", (uint32_t)kread64(cred + g_off.ucred_ruid) == 0);

    kva_t lab = kread64(cred + g_off.ucred_label);
    ok &= check("sandbox off", lab && kread64(lab + g_off.label_sandbox) == 0);

    kva_t st   = kread64(self + g_off.proc_task);
    kva_t port = kread64(st + g_off.task_itk);
    kva_t kp   = proc_find(0);
    kva_t ktask = kread64(kp + g_off.proc_task);
    ok &= check("task port", kread64(port + g_off.ipc_port_kobject) == ktask);
    ok &= check("port active", (uint32_t)kread64(port) == 0x80000002u);

    kva_t mnt  = kread64(kaddr(g_off.apfs_mnt));
    uint64_t fl = kread64(mnt + g_off.mount_flags);
    ok &= check("ssv off", (fl & (1ULL << 3)) == 0);
    ok &= check("mount rw", (fl & 1ULL) == 0);

    ok &= check("cs disabled", mela_get32(kaddr(g_off.cs_enforcement_disable)) == 1);
    ok &= check("pe debugger", mela_get32(kaddr(g_off.pe_i_can_has_debugger)) == 0x52800020u);
    ok &= check("dyld policy", mela_get32(kaddr(g_off.amfi_check_dyld_policy)) == 0x52800000u);

    const char *r = getenv("MELA_SIM_ROOT");
    char plist[512];
    snprintf(plist, sizeof plist, "%s/Library/LaunchDaemons/com.melatonin.app.plist",
             r ? r : "");
    ok &= check("launchd job", access(plist, R_OK) == 0);

    /* the job must point at the rootful daemon path, not a rootless prefix */
    {
        char buf[1024] = {0};
        FILE *f = fopen(plist, "r");
        size_t n = f ? fread(buf, 1, sizeof buf - 1, f) : 0;
        if (f) fclose(f);
        ok &= check("launchd daemon path",
                    n > 0 && strstr(buf, MELA_DAEMON) != NULL);
        ok &= check("launchd daemon args",
                    n > 0 && strstr(buf, "--daemon") != NULL);
    }

    /* simulate drift, then let the daemon tick repair it */
    uint32_t zero = 0;
    kwrite(kaddr(g_off.cs_enforcement_disable), &zero, sizeof zero);
    int tick = mela_daemon_tick();
    ok &= check("daemon reapply",
                tick == 0 && mela_get32(kaddr(g_off.cs_enforcement_disable)) == 1);
    ok &= check("amfid found", amfi_flush_cache() == 1);
    ok &= check("selftest", mela_selftest(0) == 0);

    /* patch layer: encodings and range guard */
    kva_t fn = kaddr(g_off.pe_i_can_has_debugger);
    ok &= check("patch b", mela_patch_b(fn, fn + 0x100) == 0 &&
                            mela_get32(fn) == (0x14000000u | (0x100 >> 2)));
    ok &= check("patch range", mela_patch_b(fn, fn + 0x40000000) != 0);
    ok &= check("patch bl", mela_patch_bl(fn, fn + 0x40) == 0 &&
                            mela_get32(fn) == (0x94000000u | (0x40 >> 2)));
    ok &= check("patch ret", mela_patch_ret(fn) == 0 && mela_get32(fn) == 0xD65F03C0u);

    /* hashing: canonical vectors, then cdhash fallback on an unsigned file */
    uint8_t d1[20], d2[32], cd[20];
    mela_sha1("abc", 3, d1);
    mela_sha256("abc", 3, d2);
    ok &= check("sha1", hexeq(d1, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    ok &= check("sha256", hexeq(d2, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    mela_sha256("", 0, d2);
    ok &= check("sha256 empty", hexeq(d2, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    mela_cdhash_mem("abc", 3, cd);
    ok &= check("cdhash fallback", hexeq(cd, 20,
        "ba7816bf8f01cfea414140de5dae2223b00361a3"));

    /* trust cache lookup + inject into a free slot */
    uint8_t h0[20], h3[20];
    memset(h0, 0x11, sizeof h0);
    memset(h3, 0x44, sizeof h3);
    ok &= check("trust count", mela_trust_count() == 8);
    ok &= check("trust hit", mela_trust_lookup(h0) == 1);
    ok &= check("trust miss", mela_trust_lookup(h3) == 0);
    ok &= check("trust add", mela_trust_add(h3) == 0 && mela_trust_lookup(h3) == 1);
    ok &= check("trust slot", mela_trust_free_slot() == 3);

    /* trollstore-lite install: copy bundle, hash binaries, trust them */
    const char *simroot = getenv("MELA_SIM_ROOT");
    char app[512], info[1024], bin[1024], dest[1024];
    const char *pl = "<?xml version=\"1.0\"?><plist/>";

    mkdir("/tmp/melatonin-sim-src", 0755);
    snprintf(app, sizeof app, "/tmp/melatonin-sim-src/InstallTest.app");
    mkdir(app, 0755);

    snprintf(info, sizeof info, "%s/Info.plist", app);
    write_file(info, pl, strlen(pl));

    snprintf(bin, sizeof bin, "%s/InstallTest", app);
    const uint8_t mach[8] = { 0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0 };
    write_file(bin, mach, sizeof mach);

    ok &= check("install app", mela_install_app(app) == 0);

    snprintf(dest, sizeof dest, "%s/Applications/InstallTest.app/Info.plist",
             simroot ? simroot : "");
    ok &= check("install dest", access(dest, R_OK) == 0);

    snprintf(dest, sizeof dest, "%s/Applications/InstallTest.app/InstallTest",
             simroot ? simroot : "");
    uint8_t icd[20];
    ok &= check("install cdhash",
                mela_cdhash_file(dest, icd) == 0 && mela_trust_lookup(icd) == 1);

    /* wipe the table, then let the probe rebuild it from structure */
    g_off.proc_list = g_off.proc_pid = g_off.proc_ro = 0;
    g_off.proc_ucred = g_off.ucred_uid = g_off.ucred_label = 0;
    g_off.proc_task = g_off.task_itk = g_off.ipc_port_kobject = 0;
    g_off.proc_comm = 0;

    int ap = mela_offsets_autoprobe();
    ok &= check("autoprobe", ap == 0);
    ok &= check("probe list", g_off.proc_list == 0x08);
    ok &= check("probe pid", g_off.proc_pid == 0x60);
    ok &= check("probe ro", g_off.proc_ro == 0x18 && g_off.proc_ucred == 0x08);
    ok &= check("probe uid", g_off.ucred_uid == 0x18 && g_off.ucred_label == 0x78);
    ok &= check("probe task", g_off.proc_task == 0x10);
    ok &= check("probe itk", g_off.task_itk == 0x3A8 && g_off.ipc_port_kobject == 0x48);
    ok &= check("probe comm", g_off.proc_comm == 0x3C0);
    ok &= check("probe sandbox", g_off.label_sandbox == 0x10);

    printf("[test] %s\n", ok ? "all pass" : "failures above");
    return ok ? 0 : 1;
}
