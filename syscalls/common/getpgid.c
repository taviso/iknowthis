#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set/get process group.
// pid_t getpgid(pid_t pid);
SYSFUZZ(getpgid, SYS_getpgid, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getpgid, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // pid_t pid
}

