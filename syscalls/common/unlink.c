#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Delete a name and possibly the file it refers to.
// int unlink(const char *pathname);
SYSFUZZ(unlink, SYS_unlink, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_unlink,               // int
                                typelib_get_pathname(&pathname));     // const char *pathname

    g_free(pathname);
    return retcode;
}

