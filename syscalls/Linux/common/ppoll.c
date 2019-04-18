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

// Wait for some event on a file descriptor.
// int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask);
SYSFUZZ(ppoll, __NR_ppoll, SYS_NONE, CLONE_DEFAULT, 1000)
{
	glong       retcode;
	gpointer    fds;
    gpointer    timeout;
    gpointer    sigmask;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_ppoll,                                     // int
                                typelib_get_buffer(&fds, g_random_int_range(0, PAGE_SIZE)), // struct pollfd *fds
                                typelib_get_integer(),                                      // nfds_t nfds
                                typelib_get_buffer(&timeout, g_random_int_range(0, PAGE_SIZE)),
                                typelib_get_buffer(&sigmask, g_random_int_range(0, PAGE_SIZE)));

    // Clean up.
    typelib_clear_buffer(fds);
    typelib_clear_buffer(timeout);
    typelib_clear_buffer(sigmask);

    return retcode;
}
