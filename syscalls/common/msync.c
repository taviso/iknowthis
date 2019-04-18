#include <glib.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Synchronize a file with a memory map.
// int msync(void *addr, size_t length, int flags);
SYSFUZZ(msync, SYS_msync, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, SYS_msync,                                          // int
                                address,                                                        // void *addr
                                size,                                                           // size_t len
                                typelib_get_integer());                                         // int flags

    return retcode;
}

