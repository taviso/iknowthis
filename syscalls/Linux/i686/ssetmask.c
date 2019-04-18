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

// Manipulation of signal mask (obsolete).
SYSFUZZ(ssetmask, __NR_ssetmask, SYS_NONE, CLONE_FORK, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_ssetmask,     // long
	                         typelib_get_integer());        // long newmask
}

