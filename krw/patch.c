#include "melatonin.h"

/* A64 instruction patch layer: branch range is +/-128MB */

int mela_write_insn(kva_t addr, uint32_t insn) {
    return kwrite(addr, &insn, sizeof insn);
}

int mela_patch_b(kva_t from, kva_t to) {
    int64_t d = (int64_t)to - (int64_t)from;
    if (d & 3) return -1;
    if (d < -(1LL << 27) || d >= (1LL << 27)) return -1;
    uint32_t imm = (uint32_t)((d >> 2) & 0x03FFFFFF);
    return mela_write_insn(from, 0x14000000u | imm);
}

int mela_patch_bl(kva_t from, kva_t to) {
    int64_t d = (int64_t)to - (int64_t)from;
    if (d & 3) return -1;
    if (d < -(1LL << 27) || d >= (1LL << 27)) return -1;
    uint32_t imm = (uint32_t)((d >> 2) & 0x03FFFFFF);
    return mela_write_insn(from, 0x94000000u | imm);
}

int mela_patch_nop(kva_t addr) { return mela_write_insn(addr, 0xD503201Fu); }
int mela_patch_ret(kva_t addr) { return mela_write_insn(addr, 0xD65F03C0u); }
