#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change timestamps of a file relative to a directory file descriptor.
// int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
SYSFUZZ(futimesat, SYS_futimesat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *filename;
    gpointer     times;
    glong        retcode;

    retcode     = spawn_syscall_lwp(this, NULL, SYS_futimesat,                                     // int
                                    typelib_get_resource(this, NULL, RES_FILE, RF_NONE),           // int dirfd
                                    typelib_get_pathname(&filename),                               // const char *filename
                                    typelib_get_buffer(&times, PAGE_SIZE));                        // const struct utimbuf *times

    typelib_clear_buffer(times);
    g_free(filename);

    return retcode;
}
