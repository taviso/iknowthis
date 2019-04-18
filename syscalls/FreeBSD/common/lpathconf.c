#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// get configurable pathname variables
// long lpathconf(const char *path, int name);
SYSFUZZ(lpathconf, SYS_lpathconf, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_lpathconf,                  // int
                                     typelib_get_pathname(&pathname),       // const char *pathname
                                     typelib_get_integer());                // int name

    // Release string.
    g_free(pathname);

    return retcode;
}
