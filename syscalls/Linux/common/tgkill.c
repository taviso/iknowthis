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

// Send signal sig to one specific thread, tgid
// long sys_tgkill (int tgid, int pid, int sig);
SYSFUZZ(tgkill, __NR_tgkill, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_tgkill,                                // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),    // int tgid
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),    // int tid
                                typelib_get_integer_range(0, NSIG));                    // int sig

    return retcode;
}
