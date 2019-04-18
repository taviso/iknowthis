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

// Examine and change blocked signals.
// long sys_rt_sigprocmask (int how, sigset_t *set, sigset_t *oset, size_t sigsetsize);
SYSFUZZ(rt_sigprocmask, __NR_rt_sigprocmask, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    set;
    gpointer    oset;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigprocmask,
                                typelib_get_integer_selection(3, SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK),  // int how
                                typelib_get_buffer(&set, sizeof(sigset_t)),                             // sigset_t *set
                                typelib_get_buffer(&oset, sizeof(sigset_t)),                            // sigset_t *oset
                                typelib_get_integer_selection(1, sizeof(guint64)));                     // size_t sigsetsize

    typelib_clear_buffer(set);
    typelib_clear_buffer(oset);

    return retcode;
}

