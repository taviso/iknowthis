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
// int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
SYSFUZZ(fstatat64, __NR_fstatat64, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    buf;
    gchar      *filename;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_fstatat64,                                  // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),         // int dirfd
                                typelib_get_pathname(&filename),                             // char *name
                                typelib_get_buffer(&buf, PAGE_SIZE),                         // struct stat *buf
                                typelib_get_integer());                                      // int flags

    typelib_clear_buffer(buf);
    g_free(filename);

    return retcode;
}

