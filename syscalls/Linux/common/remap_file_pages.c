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

// Create a non-linear file mapping.
// int remap_file_pages(void *start, size_t size, int prot, ssize_t pgoff, int flags);
SYSFUZZ(remap_file_pages, __NR_remap_file_pages, SYS_NONE, CLONE_DEFAULT, 0)
{
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    return spawn_syscall_lwp(this, NULL, __NR_remap_file_pages,                 // int
                             address,                                           // void *start
                             size,                                              // size_t size
                             typelib_get_integer(),                             // int prot
                             typelib_get_integer(),                             // ssize_t pgoff
                             typelib_get_integer());                            // int flags
}

