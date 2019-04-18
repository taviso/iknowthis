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

// Perform file readahead into page cache.
// ssize_t readahead(int fd, off64_t offset, size_t count);
SYSFUZZ(readahead, __NR_readahead, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    offset;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_readahead,                             // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_buffer(&offset, PAGE_SIZE),                 // off64_t *offset
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t count

    typelib_clear_buffer(offset);

    return retcode;
}

