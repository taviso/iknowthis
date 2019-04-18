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

// Synchronize a file’s in-core state with storage device.
// int fdatasync(int fd);
SYSFUZZ(fdatasync, __NR_fdatasync, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_fdatasync,                                // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE));      // int fd
}

