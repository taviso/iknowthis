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
// int lstat(const char *path, struct stat *sb);
SYSFUZZ(lstat, SYS_lstat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *pathname;
    gpointer    buf;
    glong       retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, SYS_lstat,                                   // int
                                typelib_get_pathname(&pathname),                         // const char *path
                                typelib_get_buffer(&buf, sizeof(struct stat)));          // struct stat *buf

    g_free(pathname);
    typelib_clear_buffer(buf);

    return retcode;
}
