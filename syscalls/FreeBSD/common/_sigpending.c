#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__sigpending
# define SYS__sigpending 52
#endif

// examine pending signals
// int sigpending(sigset_t *set);
SYSFUZZ(_sigpending, SYS__sigpending, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    set;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS__sigpending,                            // int
                                typelib_get_buffer(&set, sizeof(sigset_t)));            // struct sigaction *set

    typelib_clear_buffer(set);

    return retcode;
}

