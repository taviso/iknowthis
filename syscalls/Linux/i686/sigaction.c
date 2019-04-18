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

// Examine and change a signal action.
SYSFUZZ(sigaction, __NR_sigaction, SYS_NONE, CLONE_FORK, 0)
{
	gpointer    act;
	gpointer    oldact;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_sigaction,                                 // int
	                            typelib_get_integer(),                                      // int signum
	                            typelib_get_buffer(&act, g_random_int_range(0, 1024)),      // const struct sigaction *act
	                            typelib_get_buffer(&oldact, g_random_int_range(0, 1024)));  // struct sigaction *oldact

    typelib_clear_buffer(act);
    typelib_clear_buffer(oldact);
    
    return retcode;
}

