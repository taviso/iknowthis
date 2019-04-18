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

// Replace the signal mask for a value with the unewset value until a signal is received
// long sys_rt_sigsuspend (sigset_t *unewset, size_t sigsetsize);
// XXX: See coments in rt_sigaction about sigset_t definition.
SYSFUZZ(rt_sigsuspend, __NR_rt_sigsuspend, SYS_NONE, CLONE_DEFAULT, 100)
{
    gpointer    unewset;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigsuspend,                            // int
                                typelib_get_buffer(&unewset, sizeof(sigset_t)),            // const sigset_t *mask
                                typelib_get_integer_selection(1, sizeof(guint64)));        // size_t sigsetsize

    typelib_clear_buffer(unewset);
    return retcode;
}

