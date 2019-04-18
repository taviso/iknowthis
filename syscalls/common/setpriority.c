#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set program scheduling priority.
// int setpriority(int which, int who, int prio);
SYSFUZZ(setpriority, SYS_setpriority, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_setpriority,       // int
                             typelib_get_integer_range(0, 2),   // int which
                             typelib_get_integer(),             // int who
                             typelib_get_integer());            // int prio
}
