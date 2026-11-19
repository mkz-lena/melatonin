#ifndef MELA_H
#define MELA_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define MELA_NAME      "melatonin"
#define MELA_VERSION   "0.1.0"
#define MELA_DOMAIN    "com.melatonin.app"

/* jailbreak root. rootful: empty, everything lives at / (ldid in /usr/bin,
   daemon in /usr/libexec, packages in /var/lib/dpkg). a rootless port would
   define this as "/var/jb" and every path below follows automatically. */
#ifndef MELA_ROOT
#define MELA_ROOT ""
#endif
#define MELA_LDID      MELA_ROOT "/usr/bin/ldid"
#define MELA_DAEMON    MELA_ROOT "/usr/libexec/melatonind"
#define MELA_KERN_MIN  0xFFFFFFF000000000ULL
#define MELA_KERN_MAX  0xFFFFFFF100000000ULL
#define MELA_KV_ALIGN  0x200000ULL

/* 16K page granule, arm64e */
#define MELA_PAGE_SHIFT 14
#define MELA_PAGE_SIZE  (1ULL << MELA_PAGE_SHIFT)
#define MELA_PAGE_MASK  (MELA_PAGE_SIZE - 1)

typedef uint64_t kva_t;

struct mela_ctx {
    kva_t    kbase;
    kva_t    kslide;
    kva_t    kern_task;
    kva_t    self_task;
    kva_t    self_proc;
    kva_t    self_ucred;
    kva_t    rootvnode;
    pid_t    pid;
    uint32_t cpufamily;
    bool     rootful;
    bool     ssv_off;
    bool     primed;
};

extern struct mela_ctx g_mela;

/* virtual backend: corrupt-object primitive provided at runtime */
typedef struct {
    const char *name;
    int      (*init)(void);
    uint64_t (*read64)(kva_t);
    int      (*write64)(kva_t, uint64_t);
    int      (*read)(kva_t, void *, size_t);
    int      (*write)(kva_t, const void *, size_t);
} mela_krw_ops;

int  mela_krw_register(const mela_krw_ops *ops);
const mela_krw_ops *mela_krw(void);
int  mela_krw_ready(void);
int  mela_primitive_init(void);

/* physical backend: page-granular phys access + TTBR1 + physmap base */
typedef struct {
    const char *name;
    int      (*read)(uint64_t pa, void *buf, size_t len);
    int      (*write)(uint64_t pa, const void *buf, size_t len);
    uint64_t ttbr1;
    uint64_t phys_base;
} mela_phys_ops;

int  mela_phys_register(const mela_phys_ops *ops);
const mela_phys_ops *mela_phys(void);
int  mela_leaf_va(kva_t va, uint64_t *pa);
int  mela_virt_read(kva_t va, void *buf, size_t len);
int  mela_virt_write(kva_t va, const void *buf, size_t len);

/* raw kernel access through the active backend */
uint64_t kread64(kva_t);
int      kwrite64(kva_t, uint64_t);
int      kread(kva_t, void *, size_t);
int      kwrite(kva_t, const void *, size_t);

/* pac layer */
uint64_t mela_strip(uint64_t);
uint64_t mela_canon(uint64_t);
int      mela_is_kptr(uint64_t);
uint64_t mela_rebind(uint64_t, uint64_t key, uint64_t ctx);

/* base resolution */
int kbase_from_leak(uint64_t leak, uint64_t *base, uint64_t *slide);

/* proc / task surface */
kva_t proc_find(pid_t want);
int   for_each_proc(int (*cb)(kva_t, void *), void *arg);
int   become_root(void);
int   clear_uid_fields(kva_t ucred);
int   drop_sandbox(kva_t proc);
kva_t task_kernel_from_proc(kva_t kern_proc);
int   task_port_takeover(kva_t self_task, kva_t kernel_task);
kva_t kread_ptr(kva_t addr, int depth);

/* rootfs surface */
int   snapshot_select_live(void);
int   rootfs_remount(void);
int   resign_tree(const char *root);
int   mela_persist_install(void);

/* pipeline / daemon */
int   mela_run(void);
int   mela_apply(void);
int   mela_bootstrap(void);
int   mela_state_ok(void);
int   mela_daemon_tick(void);
int   mela_daemon_loop(int interval);
int   mela_probe_dryrun(void);
void  mela_offsets_report(const char *how);
kva_t proc_find_by_name(const char *name);
int   amfi_flush_cache(void);

/* instruction patch layer */
int   mela_write_insn(kva_t addr, uint32_t insn);
int   mela_patch_b(kva_t from, kva_t to);
int   mela_patch_bl(kva_t from, kva_t to);
int   mela_patch_nop(kva_t addr);
int   mela_patch_ret(kva_t addr);

/* image provider + selftest */
int      mela_image_open(const char *path);
void     mela_image_close(void);
uint32_t mela_selftest(int print);

/* exploit registry */
int   mela_exploit_run(void);
const char *mela_exploit_last(void);

/* runtime report */
int   mela_report(void);

/* trust cache */
int      mela_trust_prepare(void);
uint64_t mela_trust_count(void);
int      mela_trust_lookup(const uint8_t cdhash[20]);
int      mela_trust_free_slot(void);
int      mela_trust_add(const uint8_t cdhash[20]);

/* hashing + cdhash */
void mela_sha1(const void *data, size_t len, uint8_t out[20]);
void mela_sha256(const void *data, size_t len, uint8_t out[32]);
void mela_cdhash_mem(const void *data, size_t len, uint8_t out[20]);
int  mela_cdhash_file(const char *path, uint8_t out[20]);
int  mela_trust_add_file(const char *path);
int  mela_trust_add_bundle(const char *dir);

/* app install (trollstore-lite path) */
int  mela_install_app(const char *src);
int  mela_cli_trust(const char *path);
int  mela_cli_install(const char *path);

/* amfi / code-sign surface */
int      amfi_enable(void);
int      mela_patch_return_true(kva_t fn);
int      mela_patch_return_false(kva_t fn);
uint32_t mela_get32(kva_t addr);

static inline kva_t kaddr(kva_t off) { return g_mela.kbase + off; }

#endif
