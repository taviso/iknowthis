#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/sysctl.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"
#include "compat.h"

// Read/write system parameters.
// int _sysctl(struct __sysctl_args *args);
SYSFUZZ(_sysctl, __NR__sysctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong                   retcode = -1;
    gsize                   avail   = PAGE_SIZE;
    struct __sysctl_args    args    = {
        .name       = g_new(gint, 2),
        .nlen       = 2,
        .oldval     = typelib_get_buffer(NULL, PAGE_SIZE),
        .oldlenp    = &avail,
        .newval     = NULL,
        .newlen     = 0,
    };

    // This system call is bizarre.
    args.name[1]    = typelib_get_integer_range(0, 64);
    args.name[0]    = typelib_get_integer_selection(15, CTL_KERN,
                                                        CTL_VM,
                                                        CTL_NET,
                                                        CTL_PROC,
                                                        CTL_FS,
                                                        CTL_DEBUG,
                                                        CTL_DEV,
                                                        CTL_BUS,
                                                        CTL_ABI,
                                                        CTL_CPU,
                                                        CTL_ARLAN,
                                                        CTL_S390DBF,
                                                        CTL_SUNRPC,
                                                        CTL_PM,
                                                        CTL_FRV);

    retcode = spawn_syscall_lwp(this, NULL, __NR__sysctl,   // int
                                &args);                     // struct __sysctl_args *args

    // Clean up
    typelib_clear_buffer(args.oldval);

    g_free(args.name);

    return retcode;
}

