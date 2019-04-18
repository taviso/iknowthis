#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set real, effective and saved user or group ID.
// int setresuid(uid_t ruid, uid_t euid, uid_t suid);
SYSFUZZ(setresuid, SYS_setresuid, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_setresuid,                 // int
                             typelib_get_integer(),                     // uid_t ruid
                             typelib_get_integer(),                     // uid_t euid
                             typelib_get_integer());                    // uid_t suid
}
