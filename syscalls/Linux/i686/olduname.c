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

// Get name and information about current kernel.
SYSFUZZ(olduname, __NR_olduname, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    buf;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_olduname,                                  // int
	                            typelib_get_buffer(&buf, g_random_int_range(0, 0x1000)));   // struct utsname *buf

    typelib_clear_buffer(buf);
    return retcode;
}

