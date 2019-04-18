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

// Suspend execution of the currently running thread.
// long sys_clock_nanosleep (clockid_t which_clock, int flags, const struct timespec *rqtp, struct timespec *rmtp);
SYSFUZZ(clock_nanosleep, __NR_clock_nanosleep, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    rqtp;
    gpointer    rmtp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_clock_nanosleep,                                           // long
                                typelib_get_integer(),                                                      // clockid_t which_clock,
                                typelib_get_integer(),                                                      // int flags
                                typelib_get_buffer(&rqtp, g_random_int_range(0, 8192)),                     // const struct timespec *rqtp
                                typelib_get_buffer(&rmtp, g_random_int_range(0, 8192)));                    // struct timespec *rmtp
    typelib_clear_buffer(rqtp);
    typelib_clear_buffer(rmtp);
    return retcode;
}

