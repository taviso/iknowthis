#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set program scheduling priority.
// int getpriority(int which, int who);
SYSFUZZ(getpriority, SYS_getpriority, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getpriority,          // int
                             typelib_get_integer(),                // int which
                             typelib_get_integer());               // int who
}

