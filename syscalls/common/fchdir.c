#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change working directory.
// int fchdir(int fd);
SYSFUZZ(fchdir, SYS_fchdir, SYS_NONE, CLONE_DEFAULT, 0)
{
    return syscall_fast(SYS_fchdir,                                                     // int
                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE));           // int fd
}
