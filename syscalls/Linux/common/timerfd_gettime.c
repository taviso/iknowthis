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

// Timers that notify via file descriptors.
// int timerfd_gettime(int fd, struct itimerspec *curr_value);
SYSFUZZ(timerfd_gettime, __NR_timerfd_gettime, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    value;

    retcode = spawn_syscall_lwp(this, NULL, __NR_timerfd_gettime,                                           // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                        // int fd
                                typelib_get_buffer(&value, PAGE_SIZE));                                     // struct itimerspec *value

    typelib_clear_buffer(value);
    return retcode;
}
