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

// Start/stop swapping to file/device.
SYSFUZZ(swapon, __NR_swapon, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
	gchar   *path;
	glong    retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_swapon,                                    // int
	                            typelib_get_pathname(&path),                                // const char *path
	                            typelib_get_integer());                                     // int swapflags

    g_free(path);

    return retcode;
}

