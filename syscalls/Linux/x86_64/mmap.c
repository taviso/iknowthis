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

#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_UNINITIALIZED
# define MAP_UNINITIALIZED 0x4000000
#endif
#ifndef MAP_STACK
# define MAP_STACK 0
#endif

// Map or unmap files or devices into memory.
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SYSFUZZ(mmap, __NR_mmap, SYS_NONE, CLONE_DEFAULT, 0)
{
    gintptr     address;
    glong       retcode;
    guintptr    addr;
    gsize       length;
    gint        prot;
    gint        flags;
    gint        fd;
    goffset     offset;

    addr   = typelib_get_integer();                         // void *addr
    length = PAGE_SIZE;                                     // size_t length
    prot   = typelib_get_integer_mask(PROT_READ | PROT_WRITE | PROT_EXEC);
    flags  = typelib_get_integer_mask(MAP_SHARED
                                    | MAP_PRIVATE
                                    | MAP_FIXED
                                    | MAP_ANONYMOUS
                                    | MAP_UNINITIALIZED
                                    | MAP_GROWSDOWN
                                    | MAP_DENYWRITE
                                    | MAP_EXECUTABLE
                                    | MAP_LOCKED
                                    | MAP_NORESERVE
                                    | MAP_POPULATE
                                    | MAP_NONBLOCK
                                    | MAP_STACK
                                    | MAP_HUGETLB);
    fd     = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);
    offset = typelib_get_integer_selection(1, 0);

    // Filter out flags I don't currently support.
    flags &= ~MAP_FIXED;        // Will unmap existing region, need to take care.
    flags &= ~MAP_HUGETLB;      // Can be tricky to unmap non-zero offset HUGE pages.
    flags &= ~MAP_GROWSDOWN;    // Addr must be adjusted.

    // Make the systemcall.
    retcode = syscall_fast_ret(&address, __NR_mmap, addr, length, prot, flags, fd, offset);

    if (retcode == ESUCCESS) {
        // Record the new vma.
        typelib_vma_new(this, address, length, VMA_NONE);

        // Bypassed mmap_min_addr?
        g_assert(address != 0);
    }

    return retcode;
}
