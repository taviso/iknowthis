#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Send signal to a process.
SYSFUZZ(kill, SYS_kill, SYS_SAFE, CLONE_DEFAULT, 0)
{
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_kill,                                   // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),    // pid_t pid
                                typelib_get_integer_range(0, NSIG));                    // int sig

    return retcode;
}
