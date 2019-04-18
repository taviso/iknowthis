#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Create a special or ordinary file.
// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
SYSFUZZ(mknodat, SYS_mknodat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_mknodat,                                // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int dirfd
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_integer(),                                  // mode_t mode
                                typelib_get_integer());                                 // dev_t dev

    g_free(pathname);
    return retcode;
}

