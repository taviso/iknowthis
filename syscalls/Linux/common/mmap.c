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
#include "compat.h"

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
// void *mmap(void *addr, size_t length, int prot, int flags, 
//            int fd, off_t offset);
SYSFUZZ(mmap, __NR_mmap, SYS_NONE, CLONE_DEFAULT, 0)
{
    gintptr     address;
    glong       retcode;
    struct __packed {
        guintptr    addr;
        gsize       length;
        gint        prot;
        gint        flags;
        gint        fd;
        guint       offset;
    } parameters;

    // This old system call uses the ancient calling convention of taking a
    // pointer to a block of arguments (when the number of parameters was
    // limited to a few spare registers). I use a struct to make addressing
    // them easier.

    parameters.addr   = typelib_get_integer_selection(1, NULL);        // void *addr
    parameters.length = PAGE_SIZE;                                     // size_t length
    parameters.prot   = typelib_get_integer_mask(PROT_READ
                                               | PROT_WRITE
                                               | PROT_EXEC);
    parameters.flags  = typelib_get_integer_mask(MAP_SHARED
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
    parameters.fd     = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);    // int fd
    parameters.offset = typelib_get_integer_selection(1, 0);                    // off_t offset

    // XXX FIXME: Find a region that doesn't overlap, or only overlaps with
    //            existing managed maps, as mmap will _discard_ maps that
    //            overlap with MAP_FIXED requests.
    if (parameters.flags & MAP_FIXED) {
        parameters.length   = PAGE_SIZE;
        parameters.addr     = typelib_get_buffer(NULL, PAGE_SIZE);
    }

    // XXX FIXME: These are complicated to support.
    if (parameters.flags & MAP_HUGETLB) {
        parameters.flags &= ~MAP_HUGETLB;
    }

    // Make the systemcall.
    retcode = syscall_fast_ret(&address, __NR_mmap, &parameters);

    if (retcode == ESUCCESS) {
        gsize   size    = parameters.length;
        guint   flags   = VMA_NONE;

        // First, round size up to PAGE_SIZE
        size    = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

        // Adjust address and size if it grows down.
        address = parameters.flags & MAP_GROWSDOWN
                    ? address + PAGE_SIZE
                    : address;

        // Check if this is using hugepages.
        if (parameters.flags & MAP_HUGETLB)
            flags |= VMA_HUGE;

        if (parameters.flags & MAP_FIXED) {
            typelib_clear_buffer(parameters.addr);
        } else {
            // Record the new vma.
            typelib_vma_new(this, address, size, flags);
        }

    } else {
        if (parameters.flags & MAP_FIXED) {
            typelib_clear_buffer(parameters.addr);
        }
    }

    return retcode;
}

