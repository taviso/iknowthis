#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Create a directory.
// int mkdirat(int dirfd, const char *pathname, mode_t mode);
SYSFUZZ(mkdirat, SYS_mkdirat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_mkdirat,                                            // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int dirfd
                                typelib_get_pathname(&pathname),                                    // const char *pathname
                                typelib_get_integer());                                             // mode_t mode

    g_free(pathname);
    return retcode;
}

