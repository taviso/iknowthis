#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Receive a message from a socket.
// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
SYSFUZZ(recvfrom, SYS_recvfrom, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    buf;
    gpointer    dest_addr;

    retcode = spawn_syscall_lwp(this, NULL, SYS_recvfrom,                                   // ssize_t
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int sockfd
                                      typelib_get_buffer(&buf, PAGE_SIZE),                  // void *buf
                                      typelib_get_integer_range(0, PAGE_SIZE),              // size_t len
                                      typelib_get_integer(),                                // int flags
                                      typelib_get_buffer(&dest_addr, PAGE_SIZE),            // const struct sockaddr *src_addr
                                      typelib_get_integer_range(0, PAGE_SIZE));             // socklen_t addrlen

    typelib_clear_buffer(buf);
    typelib_clear_buffer(dest_addr);
    return retcode;
}

