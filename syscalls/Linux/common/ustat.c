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

// Get file system statistics.
SYSFUZZ(ustat, __NR_ustat, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    buf;
	glong       retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_ustat,                                     // int
	                            typelib_get_integer_mask(0xffff),                           // dev_t dev, FIXME: is mask correct for dev_t?
	                            typelib_get_buffer(&buf, g_random_int_range(0, PAGE_SIZE)));// struct ustat *ubuf
    typelib_clear_buffer(buf);

    return retcode;
}

