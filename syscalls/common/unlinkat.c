#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Delete a name and possibly the file it refers to.
// int unlinkat(int dirfd, const char *pathname, int flags);
SYSFUZZ(unlinkat, SYS_unlinkat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_unlinkat,                                           // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int dirfd
                                typelib_get_pathname(&pathname));                                   // const char *pathname

    g_free(pathname);

    return retcode;
}

