#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef CLOCK_MONOTONIC_RAW
# define CLOCK_MONOTONIC_RAW 4
#endif

// Set the specified clock.
// long sys_clock_settime (clockid_t which_clock, const struct timespec *tp);
SYSFUZZ(clock_settime, SYS_clock_settime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    tp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_clock_settime,                                             // long
                                typelib_get_integer(),                                                     // clockid_t which_clock
                                typelib_get_buffer(&tp, sizeof(struct timespec)));                         // const struct timespec *tp
    typelib_clear_buffer(tp);

    return retcode;
}
