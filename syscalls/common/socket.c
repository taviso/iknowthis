#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return close(fd) != -1;
}

// Create an endpoint for communication.
// int socket(int domain, int type, int protocol);
SYSFUZZ(socket, SYS_socket, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       fd;
    glong       retcode;

    retcode = syscall_fast_ret(&fd, SYS_socket,                         // int
                               typelib_get_integer_range(0, 32),        // int domain
                               typelib_get_integer_range(0, 16),        // int type
                               typelib_get_integer_selection(1, 0));    // int protocol

    // Check for new socket.
    if (retcode == ESUCCESS) {
        typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
    }

    return retcode;
}

