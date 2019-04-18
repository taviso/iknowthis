#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Read from a file descriptor.
SYSFUZZ(preadv, SYS_preadv, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    buffer;

    // Execute systemcall.
    // XXX FIXME BROKEN
    retcode = spawn_syscall_lwp(this, NULL, SYS_preadv,                                     // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int fd
                                typelib_get_buffer(&buffer, PAGE_SIZE),                     // void *buf
                                typelib_get_integer_range(0, PAGE_SIZE),                    // size_t count
                                typelib_get_integer());                                     // off_t offset

    // Clean up.
    typelib_clear_buffer(buffer);

    return retcode;
}
