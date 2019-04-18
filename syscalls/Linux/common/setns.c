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

// XXX remove this, just to test compatability while kernel headers lag behind.
#ifndef __NR_setns
# if defined(__i386__)
#  define __NR_setns 346
# elif defined(__x86_64__)
#  define __NR_setns 308
# else
#  error please define __NR_setns for your arch
# endif
#endif

// int setns(int fd, int nstype)
SYSFUZZ(setns, __NR_setns, SYS_FAIL, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_setns,                                // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),   // int fd
                             typelib_get_integer());                                // int nstype
}

