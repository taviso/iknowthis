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

// Returns information on overall system statistics.
SYSFUZZ(sysinfo, __NR_sysinfo, SYS_NONE, CLONE_DEFAULT, 0)
{
	glong       retcode;
	gpointer    info;

	retcode = syscall_fast(__NR_sysinfo,                                                    // int
	                       typelib_get_buffer(&info, g_random_int_range(0, 0x1000)));       // struct sysinfo *info

    typelib_clear_buffer(info);
    return retcode;
}

