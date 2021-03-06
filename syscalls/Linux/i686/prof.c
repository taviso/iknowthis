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

// Unimplemented system call.
SYSFUZZ(prof, __NR_prof, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_prof);
}

