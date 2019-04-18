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

// Set the time on a POSIX.1b interval timer
// long sys_timer_settime (timer_t timer_id, int flags, const struct itimerspec *new_setting, struct itimerspec *old_setting);
SYSFUZZ(timer_settime, __NR_timer_settime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    new_setting;
    gpointer    old_setting;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_timer_settime,
                                typelib_get_integer(),                                                  // timer_t timer_id
                                typelib_get_integer(),                                                  // int flags
                                typelib_get_buffer(&new_setting, g_random_int_range(0, 8192)),          // const struct itimerspec *new_setting
                                typelib_get_buffer(&old_setting, g_random_int_range(0, 8192)));         // struct itimerspec *old_setting

    typelib_clear_buffer(old_setting);
    typelib_clear_buffer(new_setting);

    return retcode;
}

