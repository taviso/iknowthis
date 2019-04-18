#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Create a pair of connected sockets.
// int socketpair(int domain, int type, int protocol, int sv[2]);
SYSFUZZ(socketpair, __NR_socketpair, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gint        sv[2];

    retcode = syscall_fast(__NR_socketpair,                         // int
                           typelib_get_integer_range(0, 32),        // int domain
                           typelib_get_integer_range(0, 16),        // int type
                           typelib_get_integer_selection(1, 0),     // int protocol
                           sv);                                     // int sv[2]

    // Check for new socket.
    if (retcode == ESUCCESS) {
        typelib_add_resource(this, sv[0], RES_FILE, RF_NONE, destroy_open_file);
        typelib_add_resource(this, sv[1], RES_FILE, RF_NONE, destroy_open_file);
    }

    return retcode;
}

