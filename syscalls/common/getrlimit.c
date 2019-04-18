#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef __RLIMIT_NLIMITS
# define __RLIMIT_NLIMITS RLIM_NLIMITS
#endif

// Get/set resource limits.
// int getrlimit(int resource, struct rlimit *rlim);
SYSFUZZ(getrlimit, SYS_getrlimit, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    rlim;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getrlimit,                                  // int
                                typelib_get_integer_range(0, __RLIMIT_NLIMITS),             // int resource
                                typelib_get_buffer(&rlim, sizeof(struct rlimit)));          // struct rlimit *rlim

    typelib_clear_buffer(rlim);
    return retcode;
}

