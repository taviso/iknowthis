#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// ANSI C signal handling.
SYSFUZZ(signal, __NR_signal, SYS_NONE, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_signal,                           // sighandler_t
                             typelib_get_integer(),                             // int signum
                             typelib_get_integer());                            // sighandler_t handler
}
