#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get file status.
// int fstat(int fd, struct stat *buf);
SYSFUZZ(fstat, SYS_fstat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    buf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_fstat,                                       // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),         // int fd
                                typelib_get_buffer(&buf, sizeof(struct stat)));              // struct stat *buf

    typelib_clear_buffer(buf);

    return retcode;
}

