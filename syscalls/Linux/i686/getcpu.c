#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Determine CPU and NUMA node on which the calling thread is running.
// int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
SYSFUZZ(getcpu, __NR_getcpu, SYS_NONE, CLONE_DEFAULT, 1000)
{
	gpointer    cpu;
    gpointer    node;
    gpointer    tcache;
    gint        retcode;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_getcpu,
                                typelib_get_buffer(&cpu, g_random_int_range(0, PAGE_SIZE)),
                                typelib_get_buffer(&node, g_random_int_range(0, PAGE_SIZE)),
                                typelib_get_buffer(&tcache, g_random_int_range(0, PAGE_SIZE)));

    // Clean up.
    typelib_clear_buffer(cpu);
    typelib_clear_buffer(node);
    typelib_clear_buffer(tcache);

    return retcode;
}
