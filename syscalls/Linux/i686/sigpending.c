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

// Examine pending signals.
SYSFUZZ(sigpending, __NR_sigpending, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    set;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_sigpending,                            // int
	                            typelib_get_buffer(&set, g_random_int_range(0, 32)));   // sigset_t *set

    typelib_clear_buffer(set);

    return retcode;
}

