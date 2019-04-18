#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// revoke file access
// int revoke(const char *path);
SYSFUZZ(revoke, SYS_revoke, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_revoke,                      // int
                                     typelib_get_pathname(&pathname));       // const char *pathname

    // Release string.
    g_free(pathname);

    return retcode;
}
