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
#include <sys/time.h>
#include <sys/resource.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef __NR_prlimit64
# if defined(__x86_64__)
#  define __NR_prlimit64 302
# else
#  error please define __NR_prlimit64 for your architecture
# endif
#endif

// Get/set resource limits.
// int prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);
SYSFUZZ(prlimit64, __NR_prlimit64, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    new_rlim;
    gpointer    old_rlim;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_prlimit64,                                 // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),        // pid_t pid
                                typelib_get_integer_range(0, RLIM_NLIMITS),                 // int resource
                                typelib_get_buffer(&new_rlim, PAGE_SIZE),                   // const struct rlimit64 *new_rlim
                                typelib_get_buffer(&old_rlim, PAGE_SIZE));                  // const struct rlimit64 *old_rlim

    typelib_clear_buffer(new_rlim);
    typelib_clear_buffer(old_rlim);
    return retcode;
}

