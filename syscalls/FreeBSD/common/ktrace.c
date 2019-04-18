#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// process tracing
// int ktrace(const char *tracefile, int ops, int trpoints, int pid);
SYSFUZZ(ktrace, SYS_ktrace, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar *pathname;
    glong  retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_ktrace,                                             // int
                                typelib_get_pathname(&pathname),                                    // const char *tracefile
                                typelib_get_integer(),                                              // int ops
                                typelib_get_integer(),                                              // int trpoints
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE));               // int pid


    g_free(pathname);
    return retcode;
}

