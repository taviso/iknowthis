#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Truncate a file to a specified length.
// truncate or extend a file to a specified length
SYSFUZZ(truncate, SYS_truncate, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gchar      *filename;

    retcode = spawn_syscall_lwp(this, NULL, SYS_truncate,                               // int
                                typelib_get_pathname(&filename),                        // const char *path
                                typelib_get_integer());                                 // off_t length


    g_free(filename);

    return retcode;
}

