#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Synchronous I/O multiplexing.
// int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
SYSFUZZ(select, SYS_select, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    readfds;
    gpointer    writefds;
    gpointer    exceptfds;
    gpointer    timeout;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_select,                                       // int
                                typelib_get_integer(),                                        // int nfds
                                typelib_get_buffer(&readfds, g_random_int_range(0, 1024)),    // fd_set *readfds
                                typelib_get_buffer(&writefds, g_random_int_range(0, 1024)),   // fd_set *writefds
                                typelib_get_buffer(&exceptfds, g_random_int_range(0, 1024)),  // fd_set *exceptfds
                                typelib_get_buffer(&timeout, g_random_int_range(0, 1024)));   // struct timeval *timeout

    typelib_clear_buffer(readfds);
    typelib_clear_buffer(writefds);
    typelib_clear_buffer(exceptfds);
    typelib_clear_buffer(timeout);

    return retcode;
}
