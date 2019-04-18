#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// This fuzzer is disabled by default, as file descriptors are closed as part
// of the normal fuzzing process. It's safe to enable it if you want it for
// some reason, but it might reduce coverage elsewhere.

// Close a file descriptor.
// int close(int fd);
SYSFUZZ(close, SYS_close, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_close,                                          // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_TAKEOWNERSHIP));  // int fd
}
