#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Delete a directory.
// int rmdir(const char *path);
SYSFUZZ(rmdir, SYS_rmdir, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_rmdir,                                              // int
                                typelib_get_pathname(&pathname));                                   // const char *pathname

    g_free(pathname);
    return retcode;
}

