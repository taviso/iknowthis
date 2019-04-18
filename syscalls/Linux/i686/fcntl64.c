#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef F_DUPFD_CLOEXEC
# define F_DUPFD_CLOEXEC (1024+6)
#endif


// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Manipulate file descriptor.
// int fcntl(int fd, int cmd, ... /* arg */ );
SYSFUZZ(fcntl64, __NR_fcntl64, SYS_NONE, CLONE_DEFAULT, 0)
{
    guint       cmd;
    guintptr    arg;
    gint        result;
    gint        retcode;

    // Choose a random cmd and arg.
    cmd     = typelib_get_integer();
    arg     = typelib_get_integer();

    // Decide what to do based on cmd.
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
            arg     = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl64,                            // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                        cmd,                                                    // int cmd
                                        arg);

            // Check if I have a new fd.
            if (retcode == ESUCCESS)
                typelib_add_resource(this, result, RES_FILE, RF_NONE, destroy_open_file);

            return retcode;
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl64,                        // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        typelib_get_buffer((void **)(&arg), PAGE_SIZE));

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(arg));

            return retcode;
        case F_SETSIG:
            // I don't want no crazy signal.
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl64,                        // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        SIGIO);                                             // long pid
            return retcode;
        case F_SETOWN:
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl64,                          // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int fd
                                        cmd,                                                  // int cmd
                                        typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // long pid

            return retcode;
        case F_SETFL:
            // Maybe set O_NONBLOCK
        default:
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl64,                        // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        arg);
    }

    // Try to work out what happened.
    if (retcode == EFAULT) {
        g_critical("fcntl64 cmd %#x returned EFAULT, fixme", cmd);
    }

    return retcode;
}

