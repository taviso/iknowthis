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

// Change I/O privilege level.
// int iopl(int level);
SYSFUZZ(iopl, __NR_iopl, SYS_NONE, CLONE_DEFAULT, 0)
{
	gint    level;
	glong   retcode;
    
    level   = typelib_get_integer_range(0, 3);

	retcode = syscall_fast(__NR_iopl,           // int
	                       level);              // int level


    if (level != 0) {
    	g_assert_cmpint(retcode, !=, ESUCCESS);
    }
    
    return retcode;
}

