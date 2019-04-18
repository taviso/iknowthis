#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Apply or remove an advisory lock on an open file.
// int flock(int fd, int operation);
SYSFUZZ(flock, SYS_flock, SYS_NONE, CLONE_DEFAULT, 100)
{
    return spawn_syscall_lwp(this, NULL, SYS_flock,                                     // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer());                                    // int operation
}

