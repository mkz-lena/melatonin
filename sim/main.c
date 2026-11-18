#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "melatonin.h"
#include "offsets.h"
#include "sim.h"

int mela_run(void);
int mela_daemon_loop(int interval);
int mela_probe_dryrun(void);
int mela_cli_trust(const char *path);
int mela_cli_install(const char *path);

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setenv("MELA_SIM_ROOT", "/tmp/melatonin-root", 1);

    if (argc > 1 && !strcmp(argv[1], "--dump")) {
        if (argc < 3) { fprintf(stderr, "usage: melatonin-sim --dump <path>\n"); return 2; }
        if (sim_init() != 0) { fprintf(stderr, "[sim] init failed\n"); return 1; }
        int rc = sim_dump(argv[2]);
        printf("[sim] dump %s rc=%d\n", argv[2], rc);
        return rc == 0 ? 0 : 1;
    }

    if (argc > 1 && !strcmp(argv[1], "--image")) {
        if (argc < 3) { fprintf(stderr, "usage: melatonin-sim --image <path> [probe]\n"); return 2; }
        int rc = mela_image_open(argv[2]);
        if (rc != 0) { fprintf(stderr, "[sim] image open rc=%d\n", rc); return 1; }

        printf("[sim] image %s\n", argv[2]);
        if (argc > 3 && !strcmp(argv[3], "probe")) {
            rc = mela_probe_dryrun();
        } else {
            rc = mela_run();
            if (rc == 0) rc = sim_verify();
        }
        printf("[sim] exit %d\n", rc);
        return rc;
    }

    printf("[sim] ram %lu MB  kbase %llx  pid %d\n",
           SIM_RAM >> 20, (unsigned long long)SIM_KBASE, getpid());

    if (sim_init() != 0) {
        fprintf(stderr, "[sim] init failed\n");
        return 1;
    }

    if (argc > 1 && !strcmp(argv[1], "--daemon")) {
        int iv = argc > 2 ? atoi(argv[2]) : 1;
        int rc = mela_daemon_loop(iv);
        printf("[sim] exit %d\n", rc);
        return rc;
    }

    if (argc > 1 && !strcmp(argv[1], "--probe")) {
        int rc = mela_probe_dryrun();
        printf("[sim] exit %d\n", rc);
        return rc;
    }

    if (argc > 1 && !strcmp(argv[1], "--report")) {
        mela_primitive_init();
        mela_offsets_seed();
        if (mela_krw_ready()) mela_offsets_probe();
        int rc = mela_report();
        printf("[sim] exit %d\n", rc);
        return rc;
    }

    if (argc > 2 && !strcmp(argv[1], "--trust")) {
        int rc = mela_cli_trust(argv[2]);
        printf("[sim] exit %d\n", rc);
        return rc;
    }

    if (argc > 2 && !strcmp(argv[1], "--install")) {
        int rc = mela_cli_install(argv[2]);
        printf("[sim] exit %d\n", rc);
        return rc;
    }

    int rc = mela_run();
    if (rc == 0) rc = sim_verify();
    printf("[sim] exit %d\n", rc);
    return rc;
}
