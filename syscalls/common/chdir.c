#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change working directory.
// int chdir(const char *path);
SYSFUZZ(chdir, SYS_chdir, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_chdir,                      // int
                                      typelib_get_pathname(&pathname));     // const char *pathname

    g_free(pathname);

    return retcode;
}
