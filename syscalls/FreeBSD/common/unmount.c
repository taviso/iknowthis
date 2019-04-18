#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Unmount file system.
// int unmount(const char *dir, int flags);
SYSFUZZ(unmount, SYS_unmount, SYS_FAIL | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gchar   *target;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_unmount,                                      // int
                                typelib_get_pathname(&target),                                // const char *target
                                typelib_get_integer());                                       // int flags

    g_free(target);

    return retcode;
}

