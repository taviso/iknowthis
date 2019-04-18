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

// Get the time remaining on a POSIX.1b interval timer.
// long sys_timer_gettime (timer_t timer_id, struct itimerspec *setting);
SYSFUZZ(timer_gettime, __NR_timer_gettime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    setting;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_timer_gettime,
                                typelib_get_integer(),                                                  // timer_t timer_id
                                typelib_get_buffer(&setting, g_random_int_range(0, 8192)));             // const struct itimerspec *setting

    typelib_clear_buffer(setting);

    return retcode;
}

