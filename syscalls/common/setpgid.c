#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set/get process group.
// int setpgid(pid_t pid, pid_t pgrp);
SYSFUZZ(setpgid, SYS_setpgid, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_setpgid,                                                                     // int
                                typelib_get_integer_selection(2, 0, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)),    // pid_t pid
                                typelib_get_integer_selection(2, 0, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)));   // pid_t pgid
    return retcode;
}

