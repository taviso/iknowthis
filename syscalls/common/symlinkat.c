#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Make a new name for a file.
// int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
SYSFUZZ(symlinkat, SYS_symlinkat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *oldpath;
    gchar   *newpath;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_symlinkat,                                      // int
                                typelib_get_pathname(&oldpath),                                 // const char *oldpath
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),            // int newdirfd
                                typelib_get_pathname(&newpath));                                // const char *newpath

    g_free(oldpath);
    g_free(newpath);

    return retcode;
}

