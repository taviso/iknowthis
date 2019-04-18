#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__sigprocmask
# define SYS__sigprocmask 48
#endif

// examine and change blocked signals
// int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
SYSFUZZ(_sigprocmask, SYS__sigprocmask, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    set;
    gpointer    oldset;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS__sigprocmask,                           // int
                                typelib_get_buffer(&set, sizeof(sigset_t)),             // const struct sigaction *act
                                typelib_get_buffer(&oldset, sizeof(sigset_t)));         // struct sigaction *oldact

    typelib_clear_buffer(set);
    typelib_clear_buffer(oldset);

    return retcode;
}

