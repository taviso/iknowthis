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

// Migrate pages.
// int migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
SYSFUZZ(migrate_pages, __NR_migrate_pages, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer    new_nodes;
    gpointer    old_nodes;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_migrate_pages,                                 // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),            // pid_t pid
                                typelib_get_integer(),                                          // unsigned long maxnode
                                typelib_get_buffer(&old_nodes, PAGE_SIZE),                      // const unsigned long *old_nodes
                                typelib_get_buffer(&new_nodes, PAGE_SIZE));                     // const unsigned long *new_nodes

    typelib_clear_buffer(old_nodes);
    typelib_clear_buffer(new_nodes);
    return retcode;
}


