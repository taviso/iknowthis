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

// Change the root file system
// int pivot_root(const char *new_root, const char *put_old);
SYSFUZZ(pivot_root, __NR_pivot_root, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
	gchar       *new_root;
	gchar       *put_old;
	glong        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_pivot_root,                            // int
	                            typelib_get_pathname(&new_root),                        // const char *new_root
	                            typelib_get_pathname(&put_old));                        // const char *put_old

    g_free(new_root);
    g_free(put_old);

    return retcode;
}

