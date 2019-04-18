#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Synchronize a file's in-core state with storage device.
// int fsync(int fd);
SYSFUZZ(fsync, SYS_fsync, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    return syscall_fast(SYS_fsync, typelib_get_resource(this, NULL, RES_FILE, RF_NONE));
}

