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

// Get file system statistics.
SYSFUZZ(statfs64, __NR_statfs64, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar       *filename;
	gpointer     buf;
	gint         retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_statfs64,                                // int
                                typelib_get_pathname(&filename),                          // const char *path
                                typelib_get_buffer(&buf, g_random_int_range(0, 0x1000))); // struct statfs *buf

    g_free(filename);
    typelib_clear_buffer(buf);

    return retcode;
}

