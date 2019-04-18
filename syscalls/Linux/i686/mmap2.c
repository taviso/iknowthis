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

#ifndef MAP_HUGEPAGES
# define MAP_HUGEPAGES 0x00040000
#endif

// Map or unmap files or devices into memory.
// void *mmap2(void *start, size_t length, int prot,
//             int flags, int fd, off_t pgoffset);
// XXX FIXME currently broken.
SYSFUZZ(mmap2, __NR_mmap2, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    gintptr     address;
    gint        retcode;
    guintptr    addr;
    gsize       length;
    gint        prot;
    gint        flags;
    gint        fd;
    guint       offset;

    addr   = typelib_get_integer();                                          // void *addr
    length = g_random_int_range(0, 0x10000);                                 // size_t length
    prot   = typelib_get_integer();                                          // int prot
    flags  = typelib_get_integer();                                          // int flags
    fd     = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);            // int fd
    offset = typelib_get_integer();                                          // off_t offset

    // XXX FIXME: Find a region that doesn't overlap, or only overlaps with
    //            existing managed maps, as mmap will _discard_ maps that
    //            overlap with MAP_FIXED requests.
    flags &= ~MAP_FIXED;

    // XXX: FIXME: These monsters are 256M and even anonymous maps can be offset.
    //             I need to parse maps to work out how to unmap them, so ignore for now.
    flags &= ~MAP_HUGEPAGES;

    // XXX: FIXME: These are confusing to unmap, address returned is rounded
    //             up, but you need to unmap below. Also causes null length
    //             maps to be added..wtf.
    flags &= ~MAP_GROWSDOWN;

    // Make the systemcall.
    retcode = syscall_fast_ret(&address, __NR_mmap2, addr, length, prot, flags, fd, offset);

    if (retcode == ESUCCESS) {
        // It should always give me something page aligned.
        g_assert_cmpint(address & (getpagesize() - 1), ==, 0);

        typelib_vma_new(this, address, length, VMA_NONE);
    }

    return retcode;
}

