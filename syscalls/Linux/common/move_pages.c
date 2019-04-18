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

// Move individual pages of a process to another node.
// long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags);
SYSFUZZ(move_pages, __NR_move_pages, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    pages;
    gpointer    nodes;
    gpointer    status;
    glong       retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_move_pages,
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),            // int pid
                                typelib_get_integer(),                                          // unsigned long count
                                typelib_get_buffer(&pages, g_random_int_range(0, PAGE_SIZE)),   // void **pages
                                typelib_get_buffer(&nodes, g_random_int_range(0, PAGE_SIZE)),   // const int *nodes
                                typelib_get_buffer(&status, g_random_int_range(0, PAGE_SIZE)),  // int *status
                                typelib_get_integer());                                         // int flags

    // Clean up.
    typelib_clear_buffer(pages);
    typelib_clear_buffer(nodes);
    typelib_clear_buffer(status);

    return retcode;
}
