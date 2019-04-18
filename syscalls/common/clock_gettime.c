#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Return the current timespec value of tp for the specified clock
// long sys_clock_gettime (clockid_t which_clock, struct timespec *tp);
SYSFUZZ(clock_gettime, SYS_clock_gettime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    tp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_clock_gettime,                      // long
                                typelib_get_integer(),                              // clockid_t which_clock,
                                typelib_get_buffer(&tp, sizeof(struct timespec)));  // struct timespec *tp

    typelib_clear_buffer(tp);

    return retcode;
}

