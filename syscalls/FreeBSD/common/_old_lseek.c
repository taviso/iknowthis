#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS_old_lseek
# define SYS_old_lseek 19
#endif

// Reposition read/write file offset.
SYSFUZZ(_old_lseek, SYS_old_lseek, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_old_lseek,                                         // off_t
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),               // int fd
                             typelib_get_integer(),                                             // off_t offset
                             typelib_get_integer_range(0, 4));                                  // int whence
}
