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

// Change ownership of a file.
SYSFUZZ(lchown32, __NR_lchown32, SYS_FAIL, CLONE_DEFAULT, 0)
{
	gchar *pathname;
	gint   retcode;

	// Execute systemcall.
	retcode = spawn_syscall_lwp(this, NULL, __NR_lchown32,             // int
                                typelib_get_pathname(&pathname),       // const char *path
	                            typelib_get_integer(),                 // uid_t owner
	                            typelib_get_integer());                // gid_t group
    
    g_free(pathname);

    return retcode;
}
