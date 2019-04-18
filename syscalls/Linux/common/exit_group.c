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

// Exit all threads in a process.
// void exit_group(int status);
SYSFUZZ(exit_group, __NR_exit_group, SYS_VOID, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_exit_group,       // void
                             typelib_get_integer());            // int status
}

