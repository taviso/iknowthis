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

// Get time in seconds.
SYSFUZZ(time, __NR_time, SYS_SAFE, CLONE_DEFAULT, 0)
{
    gpointer   t;
    glong      retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_time,                                 // time_t
                                typelib_get_buffer(&t, PAGE_SIZE));                    // time_t *t

    typelib_clear_buffer(t);
    return retcode;
}
