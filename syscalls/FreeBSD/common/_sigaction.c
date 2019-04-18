#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__sigaction
# define SYS__sigaction 46
#endif

// Examine and change a signal action
// int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
SYSFUZZ(_sigaction, SYS__sigaction, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    act;
    gpointer    oldact;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS__sigaction,                             // int
                                typelib_get_buffer(&act, sizeof(struct sigaction)),     // const struct sigaction *act
                                typelib_get_buffer(&oldact, sizeof(struct sigaction))); // struct sigaction *oldact

    typelib_clear_buffer(act);
    typelib_clear_buffer(oldact);

    return retcode;
}

