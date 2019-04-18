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

// Set an alarm clock for delivery of a signal.
SYSFUZZ(alarm, __NR_alarm, SYS_BORING, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_alarm,                                   // unsigned int
                             typelib_get_integer());                                   // unsigned int seconds
}

