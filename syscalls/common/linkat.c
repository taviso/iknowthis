#include <glib.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Make a new name for a file.
// int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
SYSFUZZ(linkat, SYS_linkat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *oldpath;
    gchar *newpath;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_linkat,                                             // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int olddirfd
                                typelib_get_pathname(&oldpath),                                     // const char *oldpath
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int newdirfd
                                typelib_get_pathname(&newpath),                                     // const char *newpath
                                typelib_get_integer());                                             // int flags

    g_free(oldpath);
    g_free(newpath);

    return retcode;
}

