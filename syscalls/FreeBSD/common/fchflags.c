#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// set file flags
// int fchflags(int fd, u_long flags);
SYSFUZZ(fchflags, SYS_fchflags, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong  retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_fchflags,                                   // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int fd
                                typelib_get_integer());                                     // u_long flags

    return retcode;
}
