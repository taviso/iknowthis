#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change file last access and modification times.
// int utimes(const char *filename, const struct timeval times[2]);
SYSFUZZ(utimes, SYS_utimes, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *filename;
    gpointer     times;
    glong        retcode;

    retcode     = spawn_syscall_lwp(this, NULL, SYS_utimes,                                        // int
                                    typelib_get_pathname(&filename),                               // const char *filename
                                    typelib_get_buffer(&times, sizeof(struct timeval) * 2));       // const struct timeval times[2]

    typelib_clear_buffer(times);

    g_free(filename);

    return retcode;
}
