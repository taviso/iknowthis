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

// Unmount file system.
// int umount(const char *target);
SYSFUZZ(umount, __NR_umount, SYS_FAIL | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gchar   *target;
    gint     retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_umount,                                      // int
                                typelib_get_pathname(&target));                               // const char *target

    g_free(target);

    return retcode;
}

