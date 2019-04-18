#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Duplicate a file descriptor.
// int dup2(int oldfd, int newfd);
SYSFUZZ(dup2, SYS_dup2, SYS_NONE, CLONE_FORK, 0)
{
    glong   retcode;
    glong   result;

    retcode = spawn_syscall_lwp(this, &result, SYS_dup2,                                    // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int oldfd
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE));       // int newfd

    return retcode;
}

