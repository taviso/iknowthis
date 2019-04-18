#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set group identity.
// int setgid(gid_t gid);
SYSFUZZ(setgid, SYS_setgid, SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_setgid,                                    // int
                             typelib_get_integer_selection(2, getgid(), getegid()));    // gid_t gid
}
