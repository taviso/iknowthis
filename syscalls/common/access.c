#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Check real user's permissions for a file.
SYSFUZZ(access, SYS_access, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_access,                                             // int
                                typelib_get_pathname(&pathname),                                    // const char *pathname
                                typelib_get_integer());                                             // int mode

    g_free(pathname);

    return retcode;
}
