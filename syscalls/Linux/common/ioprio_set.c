#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set I/O scheduling class and priority.
// int ioprio_set(int which, int who, int ioprio);
SYSFUZZ(ioprio_set, __NR_ioprio_set, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_ioprio_set,                                   // int
                             typelib_get_integer(),                                         // int which
                             typelib_get_integer(),                                         // int who
                             typelib_get_integer());                                        // int ioprio
}

