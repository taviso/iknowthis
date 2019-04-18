#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Create a directory.
// int mkdir(const char *path, mode_t mode);
SYSFUZZ(mkdir, SYS_mkdir, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_mkdir,                                              // int
                                typelib_get_pathname(&pathname),                                    // const char *pathname
                                typelib_get_integer());                                             // mode_t mode

    g_free(pathname);
    return retcode;
}

