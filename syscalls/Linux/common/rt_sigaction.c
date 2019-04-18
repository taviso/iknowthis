#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// The last parameter must match the kernel's expectation for sizeof(sigset_t).
// Unfortuantely the kernel definition and the libc definition are completely
// unrelated. It's a 64bit integer on x86 and x64.

#if !defined(__i386__) && !defined(__x86_64__)
# warning you might need to hardcode the sizeof sigset_t, dont use the libc definition.
#endif

// Examine and change a signal action.
// int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
SYSFUZZ(rt_sigaction, __NR_rt_sigaction, SYS_NONE, CLONE_FORK, 0)
{
    struct sigaction act;
    gpointer         oldact;
    glong            retcode;

    // Randomize the contents.
    typelib_random_buffer(&act, sizeof(act));

    // Set some values that are validated.
    act.sa_handler      = (gpointer) typelib_get_integer_selection(2, SIG_DFL, SIG_IGN);
    act.sa_sigaction    = (gpointer) typelib_get_integer_selection(2, SIG_DFL, SIG_IGN);
    act.sa_flags        = typelib_get_integer_mask(SA_NOCLDSTOP
                                                    | SA_NOCLDWAIT
                                                    | SA_NODEFER
                                                    | SA_ONSTACK
                                                    | SA_RESETHAND
                                                    | SA_RESTART
                                                    | SA_SIGINFO);
    act.sa_restorer     = (gpointer) typelib_get_integer_selection(2, SIG_DFL, SIG_IGN);

    // Make the systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigaction,                              // int
                                typelib_get_integer_range(1, NSIG),                         // int signum
                                &act,                                                       // const struct sigaction *act
                                typelib_get_buffer(&oldact, sizeof(struct sigaction)),      // struct sigaction *oldact
                                typelib_get_integer_selection(1, sizeof(gint64)));          // size_t sigsetsize

    typelib_clear_buffer(oldact);
    return retcode;
}

