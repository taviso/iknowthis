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

// Disassociate parts of the process execution context.
SYSFUZZ(unshare, __NR_unshare, SYS_NONE, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_unshare,                                  // int
                             typelib_get_integer());                                    // int flags
}


