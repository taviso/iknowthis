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

// Get and set options on sockets.
// int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
SYSFUZZ(getsockopt, __NR_getsockopt, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    optval;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_getsockopt,                                // int
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_integer_range(0, 64),                     // int level
                                      typelib_get_integer(),                                // int optname
                                      typelib_get_buffer(&optval, PAGE_SIZE),               // const void *optval
                                      typelib_get_integer_range(0, 64));                    // socklen_t optlen


    typelib_clear_buffer(optval);
    return retcode;
}
