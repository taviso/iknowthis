#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"
#include "resource.h"

// Manipulate file descriptor.
// int fcntl(int fd, int cmd, ... /* arg */ );
SYSFUZZ(fcntl, SYS_fcntl, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       cmd;
    guintptr    arg;
    glong       result;
    glong       retcode;

    cmd     = typelib_get_integer();
    arg     = typelib_get_integer();

    // Decide what to do based on cmd.
    switch (cmd) {
        case F_DUPFD:
            arg     = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);
            retcode = spawn_syscall_lwp(this, &result, SYS_fcntl,                           // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        arg);

            // Check if I have a new fd.
            if (retcode == ESUCCESS) {
                close(result);
            }

            return retcode;
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
            retcode = spawn_syscall_lwp(this, &result, SYS_fcntl,                           // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        typelib_get_buffer((void **)(&arg), PAGE_SIZE));

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(arg));

            return retcode;
        case F_SETOWN:
            retcode = spawn_syscall_lwp(this, &result, SYS_fcntl,                             // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int fd
                                        cmd,                                                  // int cmd
                                        typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // long pid

            return retcode;
        case F_SETFL:
        default:
            retcode = spawn_syscall_lwp(this, &result, SYS_fcntl,                           // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        arg);
    }

    // Try to work out what happened.
    if (retcode == EFAULT) {
        g_critical("fcntl cmd %#lx returned EFAULT, fixme", cmd);
    }

    return retcode;
}

