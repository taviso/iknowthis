#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get session ID.
// pid_t getsid(pid_t pid);
SYSFUZZ(getsid, SYS_getsid, SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getsid, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // pid_t pid
}
