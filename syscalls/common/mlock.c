#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Lock and unlock memory.
// int mlock(const void *addr, size_t len);
SYSFUZZ(mlock, SYS_mlock, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, SYS_mlock,                          // int
                                address,                                        // void *addr
                                size);                                          // size_t len

    return retcode;
}
