#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"


// Map or unmap files or devices into memory.
// int munmap(void *addr, size_t length);
SYSFUZZ(munmap, SYS_munmap, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, SYS_munmap,                         // int
                                address,                                        // void *addr
                                size);

    if (retcode == ESUCCESS) {
        typelib_vma_stale(this, address);
    }

    return retcode;
}

