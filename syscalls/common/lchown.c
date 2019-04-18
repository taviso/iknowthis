#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change ownership of a file.
SYSFUZZ(lchown, SYS_lchown, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_lchown,                // int
                                typelib_get_pathname(&pathname),       // const char *path
                                typelib_get_integer(),                 // uid_t owner
                                typelib_get_integer());                // gid_t group

    g_free(pathname);

    return retcode;
}
