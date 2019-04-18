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

// Control interface for an epoll descriptor
// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
SYSFUZZ(epoll_ctl, __NR_epoll_ctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    event;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_epoll_ctl,                             // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_integer(),                                  // int op
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_buffer(&event, PAGE_SIZE));                 // struct epoll_event *event

    typelib_clear_buffer(event);
    return retcode;
}

