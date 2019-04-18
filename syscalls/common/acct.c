#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Switch process accounting on or off.
SYSFUZZ(acct, SYS_acct, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 1000)
{
    gchar   *filename;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_acct,                       // int
                                      typelib_get_pathname(&filename));     // const char *filename

    g_free(filename);

    return retcode;
}

