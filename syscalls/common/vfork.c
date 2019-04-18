#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef __WALL
# define __WALL 0
#endif

// Create a child process and block parent.
// pid_t vfork(void);
// XXX: not working
SYSFUZZ(vfork, SYS_vfork, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    glong   retcode;
    pid_t   pid;

    // I think the lwp syscall code may not handle this well, luckily vfork() is
    // simple enough that I can handle it here.
    retcode = syscall_fast_ret(&pid, SYS_vfork);

    // Determine what happened.
    switch (pid) {
        // In the child, don't do anything.
        case  0: syscall(SYS_exit, 0);
                 g_assert_not_reached();
        // Fork failed, just return error.
        case -1: return retcode;
    }

    g_assert_cmpint(retcode, ==, 0);

    waitpid(pid, NULL, __WALL);

    return retcode;
}

