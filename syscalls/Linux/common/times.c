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

// Get process times.
// clock_t times(struct tms *buf);
SYSFUZZ(times, __NR_times, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    buf;
	glong       retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_times,                                 // clock_t
	                            typelib_get_buffer(&buf, g_random_int_range(0, 128)));  // struct tms *buf

    typelib_clear_buffer(buf);

    return retcode;
}

