#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Give advice about use of memory.
// int madvise(void *start, size_t length, int advice);
SYSFUZZ(madvise, SYS_madvise, SYS_NONE, CLONE_DEFAULT, 0)
{
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    return spawn_syscall_lwp(this, NULL, SYS_madvise,                           // int
                             address,                                           // void *start
                             size,                                              // size_t length
                             typelib_get_integer());                            // int advice
}
