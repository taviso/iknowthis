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

// Give advice about file access.
// long fadvise64(int fd, loff_t offset, size_t len, int advice);
SYSFUZZ(fadvise64, __NR_fadvise64, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_fadvise64,                                // long
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer(),                                     // long offset
                             typelib_get_integer(),                                     // size_t len
                             typelib_get_integer());                                    // int advice
}

