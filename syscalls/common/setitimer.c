#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get or set value of an interval timer.
// int setitimer(int which, const struct itimerval *value, struct itimerval *ovalue);
SYSFUZZ(setitimer, SYS_setitimer, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    o;
    gpointer    n;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_setitimer,                              // int
                                typelib_get_integer(),                                  // int which
                                typelib_get_buffer(&n, g_random_int_range(0, 128)),     // const struct itimerval *new_value
                                typelib_get_buffer(&o, g_random_int_range(0, 128)));    // struct itimerval *old_value 

    typelib_clear_buffer(o);
    typelib_clear_buffer(n);
    return retcode;
}

