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

// Shut down part of a full-duplex connection.
// int shutdown(int sockfd, int how);
SYSFUZZ(shutdown, __NR_shutdown, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_shutdown,                                  // int
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_integer_selection(3, SHUT_RD,             // int how
                                                                       SHUT_WR,
                                                                       SHUT_RDWR));
    return retcode;
}

