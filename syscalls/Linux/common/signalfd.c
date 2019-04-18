#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
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

// Create a file descriptor for accepting signals.
// int signalfd(int fd, const sigset_t *mask, int flags);
SYSFUZZ(signalfd, __NR_signalfd, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    mask;
    glong       fd;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, &fd, __NR_signalfd,                                      // int
                                typelib_get_integer_selection(1, -1),                          // int fd
                                typelib_get_buffer(&mask, PAGE_SIZE),                          // const sigset_t *mask
                                typelib_get_integer_selection(1, sizeof(unsigned long long))); // size_t sizemask

    if (retcode == ESUCCESS) {
        // Try to limit how many signalfds are in the resource list.
        if (g_random_int_range(0, 128)) {
            close(fd);
        } else {
            typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    typelib_clear_buffer(mask);

    return retcode;
}

