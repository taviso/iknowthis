#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change data segment size.
// int brk(void *addr);
SYSFUZZ(brk, __NR_brk, SYS_DISABLED, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_brk, typelib_get_integer());
}

