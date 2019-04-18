#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Terminate the calling process.
SYSFUZZ(exit, SYS_exit, SYS_VOID | SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_exit,              // void
                             typelib_get_integer());            // int status
}
