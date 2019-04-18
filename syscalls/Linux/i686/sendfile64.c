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

// Transfer data between file descriptors.
// ssize_t sendfile64(int out_fd, int in_fd, loff_t *offset, size_t count);
SYSFUZZ(sendfile64, __NR_sendfile64, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint        retcode;
    gpointer    offset;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sendfile64,                            // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int outfd
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int infd
                                typelib_get_buffer(&offset, PAGE_SIZE),                 // loff_t *offset
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t count

    typelib_clear_buffer(offset);

    return retcode;
}
