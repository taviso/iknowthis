#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Determine whether pages are resident in memory.
// int mincore(void *addr, size_t length, unsigned char *vec);
SYSFUZZ(mincore, SYS_mincore, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    vec;
    gsize       size;
    guintptr    address;
    glong       retcode;

    typelib_get_vma(this, &address, &size);

    retcode = spawn_syscall_lwp(this, NULL, SYS_mincore,                        // int
                                address,                                        // void *start
                                size,                                           // size_t length
                                typelib_get_buffer(&vec, PAGE_SIZE));           // unsigned char *vec

    typelib_clear_buffer(vec);
    return retcode;
}

