#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set real and/or effective user or group ID.
// int setregid(gid_t rgid, gid_t egid);
SYSFUZZ(setregid, SYS_setregid, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_setregid,              // int
                             typelib_get_integer(),                 // gid_t rgid
                             typelib_get_integer());                // gid_t egid
}

