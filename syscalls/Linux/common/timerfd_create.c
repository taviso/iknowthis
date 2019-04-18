#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Timers that notify via file descriptors.
// int timerfd_create(int clockid, int flags);
SYSFUZZ(timerfd_create, __NR_timerfd_create, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong   retcode;
    glong   fd;

    retcode = spawn_syscall_lwp(this, &fd, __NR_timerfd_create,                                             // int
                                typelib_get_integer_range(0, 6),                                            // int clockid
                                typelib_get_integer_mask(O_CLOEXEC | O_NONBLOCK));                          // int flags

    if (retcode == ESUCCESS) {
        if (g_random_int_range(0, 128)) {
            close(fd);
        } else {
            typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    return retcode;
}

