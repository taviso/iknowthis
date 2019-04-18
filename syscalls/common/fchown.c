#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change ownership of a file.
// int fchown(int fd, uid_t owner, gid_t group);
SYSFUZZ(fchown, SYS_fchown, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_fchown,                                    // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer(),                                     // uid_t owner
                             typelib_get_integer());                                    // gid_t group
}
