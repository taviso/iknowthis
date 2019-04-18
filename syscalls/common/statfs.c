#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get file system statistics.
SYSFUZZ(statfs, SYS_statfs, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *filename;
    gpointer     buf;
    glong        retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_statfs,                                   // int
                                typelib_get_pathname(&filename),                          // const char *path
                                typelib_get_buffer(&buf, PAGE_SIZE));                     // struct statfs *buf

    g_free(filename);
    typelib_clear_buffer(buf);

    return retcode;
}

