#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get static priority range.
// int sched_get_priority_max(int policy);
SYSFUZZ(sched_get_priority_max, SYS_sched_get_priority_max, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_sched_get_priority_max, typelib_get_integer());    // int policy
}

