#ifndef MELA_IMAGE_H
#define MELA_IMAGE_H
#include <stdint.h>

#define MELA_IMG_MAGIC   0x4D49424AU   /* "JBIM" */
#define MELA_IMG_VERSION 1u

struct mela_image_hdr {
    uint32_t magic, version, hdr_size, reserved;
    uint64_t ttbr1;
    uint64_t kern_base;
    uint64_t ram_size;
    uint64_t load_addr;
    uint64_t self_proc;
    uint64_t pid_off;
};

int  mela_image_open(const char *path);
void mela_image_close(void);

#endif
