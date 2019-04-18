#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get file system statistics.
SYSFUZZ(fstatfs, SYS_fstatfs, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer     buf;
    glong        retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_fstatfs,                                    // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int fd
                                typelib_get_buffer(&buf, PAGE_SIZE));                       // struct statfs *buf

    typelib_clear_buffer(buf);

    return retcode;
}
