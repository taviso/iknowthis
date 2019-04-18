#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get or set value of an interval timer.
// int getitimer(int which, struct itimerval *curr_value);
SYSFUZZ(getitimer, SYS_getitimer, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    c;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getitimer,                              // int
                                typelib_get_integer_selection(3,
                                                              ITIMER_REAL,
                                                              ITIMER_VIRTUAL,
                                                              ITIMER_PROF),             // int which
                                typelib_get_buffer(&c, sizeof(struct itimerval)));      // struct itimerval *curr_value

    typelib_clear_buffer(c);

    return retcode;
}

