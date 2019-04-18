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

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Open an epoll file descriptor.
// int epoll_create(int size);
SYSFUZZ(epoll_create1, __NR_epoll_create1, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       fd;
    glong       retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, &fd, __NR_epoll_create1,                          // int
                                typelib_get_integer());                                 // int size

    if (retcode == ESUCCESS) {
        // NOTE: Because basically nothing can go wrong with epoll_create1,
        //       it will saturate all the available space in my fd list very
        //       quickly. Therefore, only allow it occassionally.
        if (g_random_int_range(0, 64)) {
            close(fd);
        } else {
            // Keep this one.
            typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    return retcode;
}
