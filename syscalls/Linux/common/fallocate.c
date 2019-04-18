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

#ifndef FALLOC_FL_KEEP_SIZE
# define FALLOC_FL_KEEP_SIZE 0x00000001
#endif

// Manipulate file space.
// int fallocate(int fd, int mode, off_t offset, off_t len);
SYSFUZZ(fallocate, __NR_fallocate, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_fallocate,                                // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer_selection(1, FALLOC_FL_KEEP_SIZE),     // int mode
                             typelib_get_integer(),                                     // off_t offset
                             typelib_get_integer());                                    // off_t len
}

