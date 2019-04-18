#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__old_stat
# define SYS__old_stat 38
#endif

// Get file status.
// int stat(const char *path, struct stat *sb);
SYSFUZZ(_old_stat, SYS__old_stat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *path;
    gpointer     buf;
    glong        retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS__old_stat,
                                typelib_get_pathname(&path),                              // const char *path
                                typelib_get_buffer(&buf, sizeof(struct stat)));           // struct stat *buf

    typelib_clear_buffer(buf);

    return retcode;
}
