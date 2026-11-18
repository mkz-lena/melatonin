#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "melatonin.h"
#include "offsets.h"
#include "image.h"
#include "sim.h"

static uint8_t *ram;

/* mirrored phys layout: PA = VA & 0x0000000FFFFFFFFF */
static uint64_t pa_of(uint64_t koff) {
    return (SIM_KBASE + koff) & 0x0000000FFFFFFFFFULL;
}

static void w64(uint64_t koff, uint64_t v) {
    memcpy(ram + pa_of(koff), &v, sizeof v);
}

static uint64_t va(uint64_t koff) { return SIM_KBASE + koff; }

static int sim_rd(uint64_t pa, void *buf, size_t n) {
    if (pa > SIM_RAM || n > SIM_RAM - pa) return -1;
    memcpy(buf, ram + pa, n);
    return 0;
}

static int sim_wr(uint64_t pa, const void *buf, size_t n) {
    if (pa > SIM_RAM || n > SIM_RAM - pa) return -1;
    memcpy(ram + pa, buf, n);
    return 0;
}

static mela_phys_ops sim_ops = {
    .name = "sim",
    .read = sim_rd,
    .write = sim_wr,
    .ttbr1 = 0,
    .phys_base = 0,
};

#define PT_L0 0x4000UL
#define PT_L1 0x8000UL
#define PT_L2 0xC000UL

static void put_desc(uint64_t tbl, uint64_t idx, uint64_t val) {
    memcpy(ram + tbl + idx * 8, &val, sizeof val);
}

static void build_tables(void) {
    uint64_t l0i = (SIM_KBASE >> 47) & 0x7FF;
    uint64_t l1i = (SIM_KBASE >> 36) & 0x7FF;
    uint64_t l2i = (SIM_KBASE >> 25) & 0x7FF;

    uint64_t blk_va = SIM_KBASE & ~0x1FFFFFFULL;
    uint64_t blk_pa = blk_va & 0x0000000FFFFFFFFFULL;

    put_desc(PT_L0, l0i, PT_L1 | 3);          /* table, valid */
    put_desc(PT_L1, l1i, PT_L2 | 3);
    put_desc(PT_L2, l2i, blk_pa | 0x401);     /* block, valid, AF */

    sim_ops.ttbr1 = PT_L0;
}

/* fake kernel objects, laid out at kbase-relative offsets */
static void fake_kernel(void) {
    const uint64_t PROC_A = 0x200000, PROC_B = 0x210000;
    const uint64_t PROC_C = 0x220000;
    const uint64_t RO_A   = 0x300000, RO_B   = 0x310000;
    const uint64_t RO_C   = 0x320000;
    const uint64_t CR_A   = 0x400000, CR_B   = 0x410000;
    const uint64_t CR_C   = 0x430000;
    const uint64_t LAB_B  = 0x420000;
    const uint64_t LAB_A  = 0x421000;
    const uint64_t LAB_C  = 0x422000;
    const uint64_t SB     = 0x440000;
    const uint64_t TSK_A  = 0x500000, TSK_B  = 0x510000;
    const uint64_t TSK_C  = 0x520000;
    const uint64_t PORT_A = 0x600000, PORT_B = 0x610000;
    const uint64_t VNODE  = 0x700000;
    const uint64_t MNT    = 0x800000;
    const uint64_t APFS   = 0x801000;
    const uint64_t SNAP   = 0x900000;

    uint64_t me = (uint64_t)getpid();

    w64(0xA1B20, va(PROC_A));                 /* allproc */

    w64(PROC_A + 0x08, va(PROC_B));           /* p_list */
    w64(PROC_A + 0x60, 0);                    /* p_pid: launchd */
    w64(PROC_A + 0x10, va(TSK_A));
    w64(PROC_A + 0x18, va(RO_A));

    w64(PROC_B + 0x08, va(PROC_C));
    w64(PROC_B + 0x60, me);
    w64(PROC_B + 0x10, va(TSK_B));
    w64(PROC_B + 0x18, va(RO_B));

    w64(PROC_C + 0x08, 0);
    w64(PROC_C + 0x60, 99);
    w64(PROC_C + 0x10, va(TSK_C));
    w64(PROC_C + 0x18, va(RO_C));
    memcpy(ram + pa_of(PROC_C + 0x3C0), "amfid", 6);
    memcpy(ram + pa_of(PROC_A + 0x3C0), "launchd", 8);
    memcpy(ram + pa_of(PROC_B + 0x3C0), "jbsim", 6);

    w64(RO_C + 0x08, va(CR_C));
    w64(RO_A + 0x08, va(CR_A));
    w64(RO_B + 0x08, va(CR_B));

    w64(CR_A + 0x18, 0);                      /* uid */
    w64(CR_A + 0x20, 0);
    w64(CR_A + 0x28, 0);
    w64(CR_A + 0x78, va(LAB_A));
    w64(CR_B + 0x18, 501);
    w64(CR_B + 0x20, 501);
    w64(CR_B + 0x28, 501);
    w64(CR_B + 0x78, va(LAB_B));              /* cr_label */
    w64(CR_C + 0x18, 99);
    w64(CR_C + 0x20, 99);
    w64(CR_C + 0x28, 99);
    w64(CR_C + 0x78, va(LAB_C));
    w64(LAB_A + 0x10, 0);                     /* kernel: no sandbox */
    w64(LAB_B + 0x10, va(SB));                /* sandbox extension */
    w64(LAB_C + 0x10, va(SB));

    /* trust cache: 8 slots, two used; global points at the table */
    const uint64_t TC = 0x230000, TCS = 0x230100, TCE = 0x231000;
    w64(TC, va(TCS));
    w64(TCS + 0x08, 8);
    w64(TCS + 0x10, va(TCE));
    memset(ram + pa_of(TCE), 0x11, 20);
    memset(ram + pa_of(TCE + 0x20), 0x22, 20);

    w64(TSK_A + 0x3A8, va(PORT_A));           /* itk_self */
    w64(TSK_B + 0x3A8, va(PORT_B));

    w64(PORT_A + 0x00, 0x80000000ULL);        /* io_bits active */
    w64(PORT_A + 0x48, va(TSK_A));
    w64(PORT_B + 0x00, 0x80000000ULL);
    w64(PORT_B + 0x48, va(TSK_B));

    w64(0x11A2F0, va(VNODE));                 /* rootvnode */
    w64(0x12C118, va(MNT));                   /* apfs_mnt */

    w64(MNT + 0x10, 1);                       /* MNT_RDONLY */
    w64(MNT + 0x18, va(APFS));
    w64(APFS + 0x10, 0xDEAD0001ULL);          /* live dev */
    w64(APFS + 0x38, va(SNAP));               /* root_info head */

    w64(SNAP + 0x40, 0x6C7070612E6D6F63ULL);  /* "com.appl" */
    w64(SNAP + 0x08, 0);                      /* next */
}

int sim_init(void) {
    ram = calloc(1, SIM_RAM);
    if (!ram) return -1;

    build_tables();
    fake_kernel();

    if (mela_phys_register(&sim_ops) != 0) return -2;

    g_mela.kbase = SIM_KBASE;
    g_mela.kslide = SIM_KBASE - OFF_KERNEL_BASE;
    g_mela.primed = true;
    return 0;
}

uint64_t sim_self_proc(void) { return va(0x210000); }

/* sparse dump: header + non-zero 16K pages only */
int sim_dump(const char *path) {
    struct mela_image_hdr h;
    memset(&h, 0, sizeof h);
    h.magic = MELA_IMG_MAGIC;
    h.version = MELA_IMG_VERSION;
    h.hdr_size = sizeof h;
    h.ttbr1 = sim_ops.ttbr1;
    h.kern_base = SIM_KBASE;
    h.ram_size = SIM_RAM;
    h.load_addr = 0;
    h.self_proc = va(0x210000);
    h.pid_off = 0x60;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (write(fd, &h, sizeof h) != (ssize_t)sizeof h) { close(fd); return -2; }
    if (ftruncate(fd, (off_t)(sizeof h + SIM_RAM)) != 0) { close(fd); return -3; }

    for (size_t off = 0; off < SIM_RAM; off += 0x4000) {
        int nz = 0;
        for (size_t i = 0; i < 0x4000 && !nz; i += 8)
            if (*(uint64_t *)(ram + off + i)) nz = 1;
        if (!nz) continue;
        if (pwrite(fd, ram + off, 0x4000, (off_t)(sizeof h + off)) != 0x4000) {
            close(fd);
            return -4;
        }
    }

    close(fd);
    return 0;
}
