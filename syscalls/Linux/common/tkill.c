#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Disabled until I can whitelist the process group leader.

// Send a signal to a thread.
// int tkill(int tid, int sig);
SYSFUZZ(tkill, __NR_tkill, SYS_NONE | SYS_DISABLED, CLONE_DEFAULT, 1000)
{
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_tkill,                                 // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),    // int tid
                                typelib_get_integer_range(0, NSIG));                    // int sig

    return retcode;
}
