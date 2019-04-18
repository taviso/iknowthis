#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change permissions of a file.
// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
SYSFUZZ(fchmodat, SYS_fchmodat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_fchmodat,                               // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int dirfd
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_integer(),                                  // mode_t mode
                                typelib_get_integer());                                 // int flags

    g_free(pathname);

    return retcode;
}
