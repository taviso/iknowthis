#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Wait for an I/O event on an epoll file descriptor.
// int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
SYSFUZZ(epoll_pwait, __NR_epoll_pwait, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    events;
    gpointer    sigmask;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_epoll_pwait,                               // int
                                typelib_get_buffer(&events, g_random_int_range(0, 8192)),   // struct epoll_event *events
                                typelib_get_integer(),                                      // maxevents
                                typelib_get_integer(),                                      // timeout
                                typelib_get_buffer(&sigmask, g_random_int_range(0, 8192))); // const sigset_t *sigmask

    typelib_clear_buffer(events);
    typelib_clear_buffer(sigmask);

    return retcode;
}
