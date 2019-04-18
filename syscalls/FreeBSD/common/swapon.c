#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// control devices for interleaved paging/swapping
// int swapon(const char *special);
SYSFUZZ(swapon, SYS_swapon, SYS_FAIL, CLONE_DEFAULT, 1000)
{
    gchar *pathname;
    glong  retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_swapon,                     // int
                                     typelib_get_pathname(&pathname));      // const char *special

    // Release string.
    g_free(pathname);

    return retcode;
}
