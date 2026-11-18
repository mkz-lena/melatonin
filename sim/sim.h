#ifndef MELA_SIM_H
#define MELA_SIM_H
#include <stdint.h>

#define SIM_RAM   (256UL * 1024 * 1024)
#define SIM_KBASE 0xFFFFFFF007004000ULL

int sim_init(void);
int sim_verify(void);
int sim_dump(const char *path);
uint64_t sim_self_proc(void);

#endif
