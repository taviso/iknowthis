#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// get list of all mounted file systems
// int getfsstat(struct statfs *buf, long bufsize, int flags);
SYSFUZZ(freebsd4_getfsstat, SYS_freebsd4_getfsstat, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    buf;

    retcode = spawn_syscall_lwp(this, NULL, SYS_freebsd4_getfsstat,                         // int
                                      typelib_get_buffer(&buf, PAGE_SIZE),                  // struct ostatfs *buf
                                      typelib_get_integer(),                                // long bufsize
                                      typelib_get_integer());                               // int flags

    typelib_clear_buffer(buf);
    return retcode;
}

