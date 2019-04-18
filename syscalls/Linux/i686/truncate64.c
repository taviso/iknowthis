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

// Truncate a file to a specified length.
SYSFUZZ(truncate64, __NR_truncate64, SYS_NONE, CLONE_DEFAULT, 0)
{
	gint        retcode;
	gchar      *filename;

	retcode = spawn_syscall_lwp(this, NULL, __NR_truncate64,                            // int
	                            typelib_get_pathname(&filename),                        // const char *path
	                            typelib_get_integer());                                 // off_t length


    g_free(filename);

    return retcode;
}

