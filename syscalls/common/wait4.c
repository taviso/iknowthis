#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Wait for process to change state, BSD style.
// pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
SYSFUZZ(wait4, SYS_wait4, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer     status;
    gpointer     rusage;
    glong        retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_wait4,                                                                  // pid_t
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                                    // pid_t pid
                                typelib_get_buffer(&status, PAGE_SIZE),                                                 // int *status
                                typelib_get_integer(),                                                                  // int options
                                typelib_get_buffer(&rusage, PAGE_SIZE));                                                // struct rusage *rusage

    typelib_clear_buffer(status);
    typelib_clear_buffer(rusage);
    return retcode;
}

