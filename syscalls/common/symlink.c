#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Make a new name for a file.
// int symlink(const char *name1, const char *name2);
SYSFUZZ(symlink, SYS_symlink, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *oldpath;
    gchar   *newpath;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_symlink,                                        // int
                                typelib_get_pathname(&oldpath),                                 // const char *oldpath
                                typelib_get_pathname(&newpath));                                // const char *newpath

    g_free(oldpath);
    g_free(newpath);

    return retcode;
}

