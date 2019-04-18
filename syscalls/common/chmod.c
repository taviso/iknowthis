#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change permissions of a file.
// int chmod(const char *path, mode_t mode);
SYSFUZZ(chmod, SYS_chmod, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_chmod,              // int
                                typelib_get_pathname(&pathname),    // const char *pathname
                                typelib_get_integer());             // mode_t mode

    g_free(pathname);
    return retcode;
}
