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

// Read directory entry.
// int readdir(unsigned int fd, struct old_linux_dirent *dirp, unsigned int count);
SYSFUZZ(readdir, __NR_readdir, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    dirp;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_readdir,                               // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // unsigned int fd
                                typelib_get_buffer(&dirp, PAGE_SIZE),                   // struct old_linux_dirent *dirp
                                typelib_get_integer_range(0, 1024));                    // unsigned int count

    typelib_clear_buffer(dirp);

    return retcode;
}

