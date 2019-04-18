#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef RUSAGE_THREAD
# define RUSAGE_THREAD 1
#endif

// Get resource usage.
// int getrusage(int who, struct rusage *usage);
SYSFUZZ(getrusage, SYS_getrusage, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    usage;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getrusage,                                                              // int
                                typelib_get_integer_selection(3, RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD),          // int who
                                typelib_get_buffer(&usage, sizeof(struct rusage)));                                     // struct rusage *usage

    typelib_clear_buffer(usage);

    return retcode;
}

