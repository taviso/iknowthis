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
SYSFUZZ(umount2, __NR_umount2, SYS_FAIL | SYS_SAFE, CLONE_DEFAULT, 0)
{
	gchar   *target;
	glong    retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_umount2,                                     // int
                                typelib_get_pathname(&target),                                // const char *target
                                typelib_get_integer());                                       // int flags
    
    g_free(target);

    return retcode;
}

