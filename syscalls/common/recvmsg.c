#include <glib.h>
#include <errno.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Receive a message from a socket.
// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
SYSFUZZ(recvmsg, SYS_recvmsg, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    msg;

    retcode = spawn_syscall_lwp(this, NULL, SYS_recvmsg,                                     // ssize_t
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&msg, PAGE_SIZE),                  // const struct msghdr *msg
                                      typelib_get_integer());                               // int flags

    typelib_clear_buffer(msg);
    return retcode;
}
