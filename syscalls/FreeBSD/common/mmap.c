#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Map or unmap files or devices into memory.
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SYSFUZZ(mmap, SYS_mmap, SYS_NONE, CLONE_DEFAULT, 0)
{
    gintptr     address;
    glong       retcode;
    gsize       size;

    size    = typelib_get_integer();
    retcode = syscall_fast_ret(&address, SYS_mmap,                                              // void *
                                         typelib_get_integer(),                                 // void *addr
                                         typelib_get_integer(),                                 // size_t length
                                         size,                                                  // int prot
                                         typelib_get_integer(),                                 // int flags
                                         typelib_get_resource(this, NULL, RES_FILE, RF_NONE),   // int fd
                                         typelib_get_integer());                                // off_t offset


    if (retcode == ESUCCESS) {
        // First, round size up to PAGE_SIZE
        size    = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

        typelib_vma_new(this, address, size, 0);
    }

    return retcode;
}

