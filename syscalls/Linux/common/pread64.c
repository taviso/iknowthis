#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Read from a file descriptor.
// ssize_t pread64(int fd, void *buf, size_t count, off_t offset);
SYSFUZZ(pread64, __NR_pread64, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    buffer;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_pread64,                                           // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                // int fd
                                typelib_get_buffer(&buffer, PAGE_SIZE),                             // void *buf
                                typelib_get_integer_range(0, PAGE_SIZE),                            // size_t count
                                typelib_get_integer());                                             // off_t offset

    // Clean up.
    typelib_clear_buffer(buffer);

    return retcode;
}
