#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

enum {
    ValidSelection,
    InvalidSelection,
    NumFuzzingStrategies,
};

// Wait for some event on a file descriptor.
// int poll(struct pollfd *fds, nfds_t nfds, int timeout);
SYSFUZZ(poll, __NR_poll, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong           retcode;
    gsize           nfds;
    struct pollfd  *fds;
    gpointer        buf;

    switch (g_random_int_range(0, NumFuzzingStrategies)) {
        // We choose a random selection of file descriptors that we have from
        // our resource pool, and add them to our fds array, with a random
        // selection of events.
        case ValidSelection:
            nfds    = g_random_int_range(0, 32);
            fds     = g_new(struct pollfd, nfds);

            for (gint i = 0; i < nfds; i++) {
                fds[i].fd       = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);
                fds[i].revents  = typelib_get_integer();
                fds[i].events   = typelib_get_integer_mask(POLLIN
                                                         | POLLPRI
                                                         | POLLOUT
                                                         | POLLRDHUP
                                                         | POLLERR
                                                         | POLLHUP
                                                         | POLLNVAL
                                                         | POLLRDNORM
                                                         | POLLRDBAND
                                                         | POLLWRNORM
                                                         | POLLWRBAND
                                                         | POLLMSG);
            }

            // I pass three example timeouts, otherwise it favours waiting
            // forverer. -1, means infinite timeout, 0 means don't wait, and 1
            // means wait 1 milisecond.
            retcode = spawn_syscall_lwp(this, NULL, __NR_poll,                                      // int
                                        fds,                                                        // struct pollfd *fds
                                        nfds,                                                       // nfds_t nfds
                                        typelib_get_integer_selection(3, -1, 0, 1));                // int timeout

            // Clean up.
            g_free(fds);
            break;

        // We just pass random garbage.
        case InvalidSelection:
            retcode = spawn_syscall_lwp(this, NULL, __NR_poll,                                      // int
                                        typelib_get_buffer(&buf, sizeof(struct pollfd)),            // struct pollfd *fds
                                        typelib_get_integer(),                                      // nfds_t nfds
                                        typelib_get_integer_selection(3, -1, 0, 1));                // int timeout

            // Clean up.
            typelib_clear_buffer(buf);
            break;
    }

    return retcode;
}
