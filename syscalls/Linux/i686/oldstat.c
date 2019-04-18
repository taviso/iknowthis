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
SYSFUZZ(oldstat, __NR_oldstat, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar       *pathname;
    gpointer    buf;
    gint        retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_oldstat,                                // int
                                typelib_get_pathname(&pathname),                         // const char *path
                                typelib_get_buffer(&buf, g_random_int_range(0, 1024)));  // struct stat *buf
    
    g_free(pathname);
    typelib_clear_buffer(buf);

    return retcode;
}

