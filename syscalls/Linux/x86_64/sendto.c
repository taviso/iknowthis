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

// Send a message on a socket.
// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
SYSFUZZ(sendto, __NR_sendto, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    buf;
    gpointer    dest_addr;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sendto,                                    // ssize_t
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&buf, PAGE_SIZE),                  // const void *buf
                                      typelib_get_integer_range(0, PAGE_SIZE),              // size_t len
                                      typelib_get_integer(),                                // int flags
                                      typelib_get_buffer(&dest_addr, PAGE_SIZE),            // const struct sockaddr *dest_addr
                                      typelib_get_integer_range(0, PAGE_SIZE));             // socklen_t addrlen

    typelib_clear_buffer(buf);
    typelib_clear_buffer(dest_addr);
    return retcode;
}

