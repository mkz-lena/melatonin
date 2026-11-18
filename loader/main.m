#import <Foundation/Foundation.h>
#include <stdlib.h>
#include <string.h>
#include "melatonin.h"
#include "offsets.h"

int mela_run(void);
int mela_daemon_loop(int interval);

int main(int argc, char *argv[]) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IONBF, 0);

        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "--probe")) return mela_probe_dryrun();
            if (!strcmp(argv[i], "--report")) {
                mela_primitive_init();
                mela_offsets_seed();
                if (mela_krw_ready()) mela_offsets_probe();
                return mela_report();
            }
            if (!strcmp(argv[i], "--daemon")) {
                const char *iv = getenv("MELA_INTERVAL");
                return mela_daemon_loop(iv ? atoi(iv) : 5);
            }
            if (!strcmp(argv[i], "--trust") && i + 1 < argc)
                return mela_cli_trust(argv[i + 1]);
            if (!strcmp(argv[i], "--install") && i + 1 < argc)
                return mela_cli_install(argv[i + 1]);
        }
        return mela_run();
    }
    return 0;
}
