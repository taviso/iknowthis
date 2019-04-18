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

// Get file status.
// int fstat(int fd, struct stat *buf);
SYSFUZZ(fstat64, __NR_fstat64, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    buf;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_fstat64,                                    // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),         // int fd
                                typelib_get_buffer(&buf, PAGE_SIZE));                        // struct stat *buf

    typelib_clear_buffer(buf);

    return retcode;
}

