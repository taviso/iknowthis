#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Write to a file descriptor.
SYSFUZZ(write, SYS_write, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    buffer;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_write,                                  // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_buffer(&buffer, PAGE_SIZE),                 // const void *buf
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t count

    // Clean up.
    typelib_clear_buffer(buffer);

    return retcode;
}

