#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set and get scheduling policy/parameters
// int sched_getscheduler(pid_t pid);
SYSFUZZ(sched_getscheduler, SYS_sched_getscheduler, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_sched_getscheduler, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // pid_t pid
}

