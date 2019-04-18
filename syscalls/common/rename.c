#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change the name or location of a file.
SYSFUZZ(rename, SYS_rename, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *oldpath;
    gchar *newpath;
    glong  retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_rename,                                             // int
                                typelib_get_pathname(&oldpath),                                     // const char *oldpath
                                typelib_get_pathname(&newpath));                                    // const char *newpath

    g_free(oldpath);
    g_free(newpath);
    return retcode;
}

