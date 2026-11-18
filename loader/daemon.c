#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "melatonin.h"

static volatile sig_atomic_t g_stop;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

int mela_daemon_loop(int interval) {
    if (interval < 1) interval = 5;

    struct sigaction sa;
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    int rc = mela_apply();
    printf("[%s] %s %s daemon up (rc=%d, every %ds)\n",
           MELA_NAME, MELA_DOMAIN, MELA_VERSION, rc, interval);
    if (rc == 0) mela_selftest(1);

    while (!g_stop) {
        for (int i = 0; i < interval && !g_stop; i++) sleep(1);
        if (g_stop) break;

        if (mela_daemon_tick() != 0)
            printf("[mela] tick reapplied with errors\n");
    }

    printf("[mela] daemon stop\n");
    return 0;
}
