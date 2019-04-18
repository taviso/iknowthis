#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Lock and unlock memory.
// int munlock(const void *addr, size_t len);
SYSFUZZ(munlock, SYS_munlock, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, SYS_munlock,                        // int
                                address,                                        // void *addr
                                size);                                          // size_t len

    return retcode;
}

