#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* writes a minimal arm64e mach-o with a __TEXT segment and two symbols,
   enough for tools/koff to parse. layout is fixed, no linker needed. */

#define MH_MAGIC_64   0xfeedfacfU
#define LC_SEGMENT_64 0x19U
#define LC_SYMTAB     0x2U
#define KBASE         0xFFFFFFF007004000ULL

struct mh64 {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
};
struct seg64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};
struct symtab_cmd { uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize; };
struct nl64 { uint32_t n_strx; uint8_t n_type, n_sect; uint16_t n_desc; uint64_t n_value; };

int main(int argc, char **argv) {
    const char *out = argc > 1 ? argv[1] : "fixture.kc";

    const char *names = "_allproc\0_rootvnode\0";
    const uint32_t strsize = 20;
    const uint32_t symoff = sizeof(struct mh64) + sizeof(struct seg64) + sizeof(struct symtab_cmd);
    const uint32_t nsyms = 2;
    const uint32_t stroff = symoff + nsyms * sizeof(struct nl64);

    struct mh64 mh = {
        .magic = MH_MAGIC_64, .cputype = 0x0100000c, .cpusubtype = 2,
        .filetype = 0x0b, .ncmds = 2,
        .sizeofcmds = sizeof(struct seg64) + sizeof(struct symtab_cmd),
        .flags = 0, .reserved = 0,
    };
    struct seg64 sg;
    memset(&sg, 0, sizeof sg);
    sg.cmd = LC_SEGMENT_64;
    sg.cmdsize = sizeof sg;
    strcpy(sg.segname, "__TEXT");
    sg.vmaddr = KBASE;
    sg.vmsize = 0x400000;
    sg.fileoff = 0;
    sg.filesize = stroff + strsize;
    sg.maxprot = 7; sg.initprot = 5;

    struct symtab_cmd st = {
        .cmd = LC_SYMTAB, .cmdsize = sizeof st,
        .symoff = symoff, .nsyms = nsyms,
        .stroff = stroff, .strsize = strsize,
    };
    struct nl64 syms[2];
    memset(syms, 0, sizeof syms);
    syms[0].n_strx = 1;
    syms[0].n_value = KBASE + 0x000A1B20ULL;
    syms[1].n_strx = 10;
    syms[1].n_value = KBASE + 0x0011A2F0ULL;

    FILE *f = fopen(out, "wb");
    if (!f) { perror("mkfixture"); return 1; }
    fwrite(&mh, sizeof mh, 1, f);
    fwrite(&sg, sizeof sg, 1, f);
    fwrite(&st, sizeof st, 1, f);
    fwrite(syms, sizeof syms, 1, f);
    fwrite(names, 1, strsize, f);
    fclose(f);
    return 0;
}
