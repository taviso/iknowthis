#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Create a file descriptor for event notification.
// int eventfd(unsigned int initval, int flags);
SYSFUZZ(eventfd2, __NR_eventfd2, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong   retcode;
    glong   fd;

    retcode = spawn_syscall_lwp(this, &fd, __NR_eventfd2,                                       // int
                                typelib_get_integer(),                                          // int initval
                                typelib_get_integer());                                         // int flags

    if (retcode == ESUCCESS) {
        // Stop eventfd() from spamming my file descriptor list.
        if (g_random_int_range(0, 128)) {
            close(fd);
        } else {
            typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    return retcode;
}

