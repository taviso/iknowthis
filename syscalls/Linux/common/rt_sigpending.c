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

// Examine pending signals.
// long sys_rt_sigpending (sigset_t *set, size_t sigsetsize);
SYSFUZZ(rt_sigpending, __NR_rt_sigpending, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    set;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigpending,                         // int
                                typelib_get_buffer(&set, sizeof(sigset_t)),             // sigset_t *set
                                typelib_get_integer_selection(1, sizeof(guint64))) ;    // size_t sigsetsize

    typelib_clear_buffer(set);

    return retcode;
}

