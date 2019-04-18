#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set resource limits.
SYSFUZZ(ugetrlimit, __NR_ugetrlimit, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    rlim;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_ugetrlimit,                                 // int
	                            typelib_get_integer(),                                       // int resource
	                            typelib_get_buffer(&rlim, g_random_int_range(0, 8192)));     // struct rlimit *rlim

    typelib_clear_buffer(rlim);
    return retcode;
}

