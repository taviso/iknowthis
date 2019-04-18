#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Initiate a connection on a socket.
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
SYSFUZZ(connect, SYS_connect, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    addr;

    retcode = syscall_fast(SYS_connect,                                                 // int
                           typelib_get_resource(this, NULL, RES_FILE, RF_NONE),         // int sockfd
                           typelib_get_buffer(&addr, sizeof(struct sockaddr)),          // const struct sockaddr *addr
                           typelib_get_integer_selection(1, sizeof(struct sockaddr)));  // socklen_t addrlen

    typelib_clear_buffer(addr);
    return retcode;
}

