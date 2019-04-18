#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// set file flags
// int chflags(const char *path, u_long flags);
SYSFUZZ(chflags, SYS_chflags, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_chflags,                                    // int
                                typelib_get_pathname(&pathname),                            // const char *path
                                typelib_get_integer());                                     // u_long flags

    g_free(pathname);
    return retcode;
}
