#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get and set options on sockets.
// int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
SYSFUZZ(setsockopt, SYS_setsockopt, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    optval;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_setsockopt,                                 // int
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_integer_range(0, 64),                     // int level
                                      typelib_get_integer(),                                // int optname
                                      typelib_get_buffer(&optval, PAGE_SIZE),               // const void *optval
                                      typelib_get_integer_range(0, 64));                    // socklen_t optlen


    typelib_clear_buffer(optval);
    return retcode;
}
