#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Return from signal handler and cleanup stack frame.
// int sigreturn(unsigned long __unused);
SYSFUZZ(rt_sigreturn, __NR_rt_sigreturn, SYS_DISABLED, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_rt_sigreturn,                             // int
                             typelib_get_integer());                                    // unsigned long __unused
}

