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

// Set default NUMA memory policy for a process and its children.
// int set_mempolicy(int mode, unsigned long *nodemask, unsigned long maxnode);
SYSFUZZ(set_mempolicy, __NR_set_mempolicy, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    nmask;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_set_mempolicy,                         // int
                                typelib_get_integer(),                                  // int mode
                                typelib_get_buffer(&nmask, g_random_int_range(0, 32)),  // unsigned long *nodemask
                                typelib_get_integer());                                 // unsigned long maxnode

    typelib_clear_buffer(nmask);

    return retcode;
}

