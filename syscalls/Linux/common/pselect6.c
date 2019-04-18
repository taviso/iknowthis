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

SYSFUZZ(pselect6, __NR_pselect6, SYS_NONE, CLONE_DEFAULT, 1000)
{
	glong       retcode;
    gpointer    readfds;
    gpointer    writefds;
    gpointer    exceptfds;
    gpointer    timeout;
    gpointer    sigmask;

	retcode = spawn_syscall_lwp(this, NULL, __NR_pselect6,                                      // int
                                typelib_get_integer(),                                          // int nfds
                                typelib_get_buffer(&readfds, g_random_int_range(0, PAGE_SIZE)),  // fd_set *readfds
                                typelib_get_buffer(&writefds, g_random_int_range(0, PAGE_SIZE)), // fd_set *writefds
                                typelib_get_buffer(&exceptfds, g_random_int_range(0, PAGE_SIZE)),// fd_set *exceptfds
                                typelib_get_buffer(&timeout, g_random_int_range(0, PAGE_SIZE)),  // const struct timespec *timeout
                                typelib_get_buffer(&sigmask, g_random_int_range(0, PAGE_SIZE))); // const sigset_t *sigmask
    
    typelib_clear_buffer(readfds);
    typelib_clear_buffer(writefds);
    typelib_clear_buffer(exceptfds);
    typelib_clear_buffer(timeout);
    typelib_clear_buffer(sigmask);

    return retcode;
}

