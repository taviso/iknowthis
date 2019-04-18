#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Create a special or ordinary file.
// Please note, mknod() can create normal files, and so is expected to succeed.
// int mknod(const char *pathname, mode_t mode, dev_t dev);
SYSFUZZ(mknod, SYS_mknod, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_mknod,                // int
                                typelib_get_pathname(&pathname),      // const char *pathname
                                typelib_get_integer(),                // mode_t mode
                                typelib_get_integer());               // dev_t dev

    g_free(pathname);
    return retcode;
}
