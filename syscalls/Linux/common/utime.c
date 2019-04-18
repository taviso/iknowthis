#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/types.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change file last access and modification times.
// int utime(const char *filename, const struct utimbuf *times);
SYSFUZZ(utime, __NR_utime, SYS_SAFE, CLONE_DEFAULT, 1000)
{
    gchar       *filename;
    gpointer     times;
    glong        retcode;

    retcode     = spawn_syscall_lwp(this, NULL, __NR_utime,                                        // int
                                    typelib_get_pathname(&filename),                               // const char *filename
                                    typelib_get_buffer(&times, sizeof(struct utimbuf)));           // const struct utimbuf *times

    typelib_clear_buffer(times);
    g_free(filename);

    return retcode;
}
