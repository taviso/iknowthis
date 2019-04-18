#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Duplicate a file descriptor.
// int dup3(int oldfd, int newfd, int flags);
SYSFUZZ(dup3, __NR_dup3, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    glong   retcode;
    glong   result;

    // XXX: BROKEN
    retcode = spawn_syscall_lwp(this, &result, __NR_dup3,                                   // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int oldfd
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int newfd
                                typelib_get_integer());                                     // int flags

    return retcode;
}
