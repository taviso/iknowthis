#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__mmap
# define SYS__mmap 71
#endif

// Map or unmap files or devices into memory.
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SYSFUZZ(_mmap, SYS__mmap, SYS_NONE, CLONE_FORK, 0)
{
    gintptr     address;
    glong       retcode;
    gsize       size;

    size    = typelib_get_integer();
    retcode = spawn_syscall_lwp(this, &address, SYS__mmap,                                             // void *
                                                typelib_get_integer(),                                 // void *addr
                                                typelib_get_integer(),                                 // size_t length
                                                size,                                                  // int prot
                                                typelib_get_integer(),                                 // int flags
                                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),   // int fd
                                                typelib_get_integer());                                // off_t offset

    return retcode;
}

