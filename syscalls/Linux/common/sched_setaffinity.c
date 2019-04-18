#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set and get a process’s CPU affinity mask.
// int sched_setaffinity(pid_t pid, unsigned int cpusetsize, cpu_set_t *mask);
SYSFUZZ(sched_setaffinity, __NR_sched_setaffinity, SYS_NONE, CLONE_FORK, 100)
{
    gpointer    mask;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sched_setaffinity,                             // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),            // pid_t pid
                                typelib_get_integer_range(0, PAGE_SIZE),                        // unsigned int cpusetsize
                                typelib_get_buffer(&mask, PAGE_SIZE));                          // cpu_set_t *mask

    typelib_clear_buffer(mask);

    return retcode;
}

