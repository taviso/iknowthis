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

// Start, flush, or tune buffer-dirty-flush daemon.
// int bdflush(int func, long *address);
// int bdflush(int func, long data);
SYSFUZZ(bdflush, __NR_bdflush, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    address;
    gint        retcode;

    if (g_random_boolean()) {
        retcode = spawn_syscall_lwp(this, NULL, __NR_bdflush,                                           // int
                                    typelib_get_integer_selection(3, 0, 1, 2),                          // int func
                                    typelib_get_buffer(&address, g_random_int_range(0, PAGE_SIZE)));    // long *address
        typelib_clear_buffer(address);
    } else {
    	retcode = spawn_syscall_lwp(this, NULL, __NR_bdflush,                                           // int
    	                            3,                                                                  // int func
    	                            typelib_get_integer());                                             // long data
    }

    return retcode;
}

