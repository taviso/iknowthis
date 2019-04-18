#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change process priority.
// int nice(int inc);
SYSFUZZ(nice, __NR_nice, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_nice,                            // int
                             typelib_get_integer());                           // int inc
}

