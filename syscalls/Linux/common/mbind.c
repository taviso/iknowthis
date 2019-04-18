#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set memory policy for a memory range.
// int mbind(void *addr, unsigned long len, int mode, unsigned long *nodemask, unsigned long maxnode, unsigned flags);
SYSFUZZ(mbind, __NR_mbind, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    nmask;
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, __NR_mbind,                         // int
                                address,                                        // void *addr
                                size,                                           // unsigned long len
                                typelib_get_integer(),                          // int mode
                                typelib_get_buffer(&nmask, g_random_int_range(0, 32)),  // unsigned long *nodemask,
                                typelib_get_integer(),                          // unsigned long maxnode
                                typelib_get_integer());                         // unsigned flags

    typelib_clear_buffer(nmask);
    return retcode;
}

