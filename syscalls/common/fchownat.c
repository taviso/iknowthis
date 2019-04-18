#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change ownership of a file.
// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
SYSFUZZ(fchownat, SYS_fchownat, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_fchownat,                                  // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int dirfd
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer(),                                     // uid_t owner
                             typelib_get_integer());                                    // gid_t group
}

