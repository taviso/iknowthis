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

// Wait for an I/O event on an epoll file descriptor.
// int epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);
SYSFUZZ(epoll_wait, __NR_epoll_wait, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    events;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_epoll_wait,                                // int
                                typelib_get_buffer(&events, g_random_int_range(0, 8192)),   // struct epoll_event *events
                                typelib_get_integer(),                                      // maxevents
                                typelib_get_integer());                                     // timeout

    typelib_clear_buffer(events);
    return retcode;
}

