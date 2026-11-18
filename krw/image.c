#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "melatonin.h"
#include "offsets.h"
#include "image.h"

static uint8_t *map;
static size_t maplen;
static struct mela_image_hdr *hdr;

static int img_rd(uint64_t pa, void *buf, size_t n) {
    if (!hdr || pa > hdr->ram_size || n > hdr->ram_size - pa) return -1;
    memcpy(buf, map + hdr->hdr_size + pa, n);
    return 0;
}

static int img_wr(uint64_t pa, const void *buf, size_t n) {
    if (!hdr || pa > hdr->ram_size || n > hdr->ram_size - pa) return -1;
    memcpy(map + hdr->hdr_size + pa, buf, n);
    return 0;
}

static mela_phys_ops img_ops = {
    .name = "image",
    .read = img_rd,
    .write = img_wr,
    .ttbr1 = 0,
    .phys_base = 0,
};

int mela_image_open(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(struct mela_image_hdr)) {
        close(fd);
        return -2;
    }

    maplen = (size_t)st.st_size;
    map = mmap(NULL, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { map = NULL; return -3; }

    hdr = (struct mela_image_hdr *)map;
    if (hdr->magic != MELA_IMG_MAGIC || hdr->version != MELA_IMG_VERSION ||
        hdr->hdr_size < sizeof *hdr ||
        hdr->hdr_size + hdr->ram_size > maplen) {
        munmap(map, maplen);
        map = NULL; hdr = NULL;
        return -4;
    }

    img_ops.ttbr1 = hdr->ttbr1;
    img_ops.phys_base = hdr->load_addr;
    if (mela_phys_register(&img_ops) != 0) return -5;

    g_mela.kbase = hdr->kern_base;
    g_mela.kslide = hdr->kern_base - OFF_KERNEL_BASE;
    g_mela.primed = true;

    /* rebind the stored self proc to this pid */
    if (hdr->self_proc && hdr->pid_off) {
        uint32_t me = (uint32_t)getpid();
        uint64_t pa = (hdr->self_proc & 0x0000000FFFFFFFFFULL) + hdr->pid_off;
        img_wr(pa, &me, sizeof me);
    }
    return 0;
}

void mela_image_close(void) {
    if (map) munmap(map, maplen);
    map = NULL; hdr = NULL; maplen = 0;
}
