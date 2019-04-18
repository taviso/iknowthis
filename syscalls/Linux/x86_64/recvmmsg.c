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

#ifndef __NR_recvmmsg
# ifdef __x86_64__
#  define __NR_recvmmsg 299
# endif
#endif

// Receive a message from a socket.
// ssize_t recvmsg(int fd, struct msghdr *mmsg, unsigned int vlen, unsigned int flags, struct timespec *timeout);
SYSFUZZ(recvmmsg, __NR_recvmmsg, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    mmsg;
    gpointer    timeout;

    retcode = spawn_syscall_lwp(this, NULL, __NR_recvmmsg,                                  // ssize_t
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int fd
                                      typelib_get_buffer(&mmsg, PAGE_SIZE),                 // const struct msghdr *mmsg
                                      typelib_get_integer(),                                // unsigned int vlen
                                      typelib_get_integer(),                                // unsigned int flags
                                      typelib_get_buffer(&timeout, PAGE_SIZE));             // struct timespec *timeout

    typelib_clear_buffer(mmsg);
    typelib_clear_buffer(timeout);

    return retcode;
}
