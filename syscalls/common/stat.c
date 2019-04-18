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
// int stat(const char *path, struct stat *sb);
SYSFUZZ(stat, SYS_stat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *path;
    gpointer     buf;
    glong        retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_stat,
                                typelib_get_pathname(&path),                              // const char *path
                                typelib_get_buffer(&buf, sizeof(struct stat)));           // struct stat *buf

    typelib_clear_buffer(buf);

    return retcode;
}

