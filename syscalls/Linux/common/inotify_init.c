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

// Initialize an inotify instance
// int inotify_init(void)
SYSFUZZ(inotify_init, __NR_inotify_init, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong    retcode;
    glong    fd;

    retcode = spawn_syscall_lwp(this, &fd, __NR_inotify_init);                                   // int

    if (retcode == ESUCCESS) {
        // Because very little can go wrong with inotify_init, it will quickly
        // saturate all of my available file descriptors. So only keep them
        // occasionally.
        if (g_random_int_range(0, 128)) {
            close(fd);
        } else {
            typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    return retcode;
}

