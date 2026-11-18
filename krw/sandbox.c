#include "melatonin.h"
#include "offsets.h"

int drop_sandbox(kva_t proc) {
    if (!mela_krw_ready() || !proc) return -1;

    kva_t ro    = kread64(proc + g_off.proc_ro);
    if (!mela_is_kptr(ro)) return -1;

    kva_t cred  = kread64(ro + g_off.proc_ucred);
    if (!mela_is_kptr(cred)) return -1;

    kva_t label = kread64(cred + g_off.ucred_label);
    if (!label) return -1;

    /* clear the sandbox slot and its flags word */
    kwrite64(label + g_off.label_sandbox, 0);
    return 0;
}
