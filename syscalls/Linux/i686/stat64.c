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

// Get file status.
SYSFUZZ(stat64, __NR_stat64, SYS_NONE, CLONE_DEFAULT, 0)
{
	gchar       *path;
	gpointer     buf;
	gint         retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_stat64,
                                typelib_get_pathname(&path),                              // const char *path
                                typelib_get_buffer(&buf, g_random_int_range(0, 0x1000))); // struct stat *buf

    typelib_clear_buffer(buf);

    return retcode;
}

