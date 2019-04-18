#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Check real users permissions for a file.
// int faccessat(int dirfd, const char *pathname, int mode, int flags);
SYSFUZZ(faccessat, SYS_faccessat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_faccessat,                                          // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int dirfd
                                typelib_get_pathname(&pathname),                                    // const char *pathname
                                typelib_get_integer_mask(R_OK | W_OK | X_OK | F_OK),                // int mode
                                typelib_get_integer());

    g_free(pathname);

    return retcode;
}
