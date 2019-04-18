#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Return from signal handler and cleanup stack frame.
SYSFUZZ(sigreturn, __NR_sigreturn, SYS_DISABLED, CLONE_FORK, 0)
{
    gint retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sigreturn,                                 // int
                                typelib_get_integer());                                     // unsigned long __unused

    return retcode;
}

