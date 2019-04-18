#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Send a message on a socket.
// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
SYSFUZZ(sendmsg, SYS_sendmsg, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    msg;

    retcode = spawn_syscall_lwp(this, NULL, SYS_sendmsg,                                    // ssize_t
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&msg, PAGE_SIZE),                  // const struct msghdr *msg
                                      typelib_get_integer());                               // int flags

    typelib_clear_buffer(msg);
    return retcode;
}
