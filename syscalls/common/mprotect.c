#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set protection on a region of memory.
// int mprotect(const void *addr, size_t len, int prot);
SYSFUZZ(mprotect, SYS_mprotect, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, SYS_mprotect,                       // int
                                address,                                        // void *addr
                                size,                                           // size_t len
                                typelib_get_integer());                         // int prot


    return retcode;
}

