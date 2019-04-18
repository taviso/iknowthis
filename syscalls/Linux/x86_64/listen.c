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

// Listen for connections on a socket.
// int listen(int sockfd, int backlog);
SYSFUZZ(listen, __NR_listen, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_listen,                                    // int
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_integer());                               // int backlog

    return retcode;
}

