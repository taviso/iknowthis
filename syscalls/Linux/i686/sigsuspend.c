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

// Wait for a signal.
SYSFUZZ(sigsuspend, __NR_sigsuspend, SYS_NONE, CLONE_DEFAULT, 100)
{
	gpointer    mask;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_sigsuspend,    // int
	                            typelib_get_buffer(&mask, g_random_int_range(0, 32)));  // const sigset_t *mask

    typelib_clear_buffer(mask);

    return retcode;
}

