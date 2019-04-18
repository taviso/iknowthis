#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change root directory.
// int chroot(const char *path);
SYSFUZZ(chroot, SYS_chroot, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gchar   *path;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_chroot,                                     // int
                                typelib_get_pathname(&path));                               // const char *path

    g_free(path);

    return retcode;
}

