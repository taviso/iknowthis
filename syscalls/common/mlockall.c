#include <glib.h>
#include <errno.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Note: enabling this will probably cause memory allocation failures elsewhere.

// Lock and unlock memory.
// int mlockall(int flags);
SYSFUZZ(mlockall, SYS_mlockall, SYS_DISABLED, CLONE_DEFAULT, 1000)
{
    return spawn_syscall_lwp(this, NULL, SYS_mlockall,                         // int
                             typelib_get_integer());                           // int flags
}

