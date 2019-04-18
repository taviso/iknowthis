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

// Set port input/output permissions.
SYSFUZZ(ioperm, __NR_ioperm, SYS_NONE, CLONE_DEFAULT, 0)
{
    // Kernel verifies from + num < IO_PERM_BITS (65536) (sys_ioperm, ioport.c)
	return spawn_syscall_lwp(this, NULL, __NR_ioperm,                                       // int
	                         typelib_get_integer_mask(0xffff),                              // unsigned long from
	                         typelib_get_integer_mask(0xffff),                              // unsigned long num
	                         typelib_get_integer_range(0, 1));                              // int turn_on
}

