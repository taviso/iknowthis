#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change file timestamps with nanosecond precision.
// int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
SYSFUZZ(utimensat, __NR_utimensat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *filename;
    gpointer     times;
    glong        retcode;

    retcode     = spawn_syscall_lwp(this, NULL, __NR_utimensat,                                    // int
                                    typelib_get_resource(this, NULL, RES_FILE, RF_NONE),           // int dirfd
                                    typelib_get_pathname(&filename),                               // const char *filename
                                    typelib_get_buffer(&times, PAGE_SIZE),                         // const struct timespec times[2]
                                    typelib_get_integer());                                        // int flags

    typelib_clear_buffer(times);
    g_free(filename);

    return retcode;
}
