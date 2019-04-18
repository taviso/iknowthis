#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// set real, effective and saved user or group.
// int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
SYSFUZZ(setresgid, SYS_setresgid, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_setresgid,                 // int
                             typelib_get_integer(),                     // gid_t rgid
                             typelib_get_integer(),                     // gid_t egid
                             typelib_get_integer());                    // gid_t sgid
}
