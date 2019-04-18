#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get the SCHED_RR interval for the named process.
// int sched_rr_get_interval(pid_t pid, struct timespec * tp);
SYSFUZZ(sched_rr_get_interval, SYS_sched_rr_get_interval, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    tp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_sched_rr_get_interval,                                  // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                    // pid_t pid
                                typelib_get_buffer(&tp, PAGE_SIZE));                                    // struct timespec * tp

    typelib_clear_buffer(tp);
    return retcode;
}

