#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Yield the processor.
// int sched_yield(void);
SYSFUZZ(sched_yield, SYS_sched_yield, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_sched_yield);                                             // int
}

