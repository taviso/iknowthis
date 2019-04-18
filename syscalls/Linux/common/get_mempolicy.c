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

// Retrieve NUMA memory policy for a process.
// int get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, unsigned long addr, unsigned long flags);
SYSFUZZ(get_mempolicy, __NR_get_mempolicy, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    mode;
    gpointer    nmask;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_get_mempolicy,                         // int
                                typelib_get_buffer(&mode, g_random_int_range(0, 32)),   // int *mode
                                typelib_get_buffer(&nmask, g_random_int_range(0, 32)),  // unsigned long *nodemask
                                typelib_get_integer(),                                  // unsigned long maxnode
                                typelib_get_vma(this, NULL, NULL),                      // unsigned long addr
                                typelib_get_integer());                                 // unsigned flags

    typelib_clear_buffer(nmask);
    typelib_clear_buffer(mode);

    return retcode;
}

