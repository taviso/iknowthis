#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change ownership of a file.
// int chown(const char *path, uid_t owner, gid_t group);
SYSFUZZ(chown, SYS_chown, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *path;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_chown,                                  // int
                                typelib_get_pathname(&path),                            // const char *path
                                typelib_get_integer_selection(1, -1),                   // uid_t owner
                                typelib_get_integer_selection(1, -1));                  // gid_t group

    g_free(path);

    return retcode;
}

