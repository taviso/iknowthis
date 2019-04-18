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
#include "resource.h"

#ifndef F_DUPFD_CLOEXEC
# define F_DUPFD_CLOEXEC (1024+6)
#endif
#ifndef F_SETPIPE_SZ
# define F_SETPIPE_SZ 1031
#endif
#ifndef F_GETPIPE_SZ
# define F_GETPIPE_SZ 1032
#endif
#ifndef F_GETOWN_EX
# define F_GETOWN_EX 0
#endif
#ifndef F_SETOWN_EX
# define F_SETOWN_EX 0
#endif

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Manipulate file descriptor.
// int fcntl(int fd, int cmd, ... /* arg */ );
SYSFUZZ(fcntl, __NR_fcntl, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       cmd;
    guintptr    arg;
    glong       result;
    glong       retcode;

    // Choose a random cmd and arg.
    cmd     = typelib_get_integer_selection(23, F_DUPFD,
                                                F_DUPFD_CLOEXEC,
                                                F_GETFD,
                                                F_SETFD,
                                                F_GETFL,
                                                F_SETFL,
                                                F_GETLK,
                                                F_SETLK,
                                                F_SETLKW,
                                                F_GETOWN,
                                                F_SETOWN,
                                                F_GETOWN_EX,
                                                F_SETOWN_EX,
                                                F_GETSIG,
                                                F_SETSIG,
                                                F_GETLEASE,
                                                F_SETLEASE,
                                                F_NOTIFY,
                                                F_SETPIPE_SZ,
                                                F_GETPIPE_SZ,
                                                F_GETLK64,
                                                F_SETLK64,
                                                F_SETLKW64);
    arg     = typelib_get_integer();

    // Decide what to do based on cmd.
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
            arg     = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl,                          // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        arg);

            // Check if I have a new fd.
            if (retcode == ESUCCESS) {
                if (g_random_int_range(0, 128)) {
                    close(result);
                } else {
                    typelib_add_resource(this, result, RES_FILE, RF_NONE, destroy_open_file);
                }
            }

            return retcode;
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:

// These only have different values on 32bit systems.
#if F_GETLK != F_GETLK64
        case F_GETLK64:
#endif
#if F_SETLK != F_SETLK64
        case F_SETLK64:
#endif
#if F_SETLKW != F_SETLKW64
        case F_SETLKW64:
#endif

#if F_GETOWN_EX != F_DUPFD
        case F_GETOWN_EX:
        case F_SETOWN_EX:
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl,                          // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        typelib_get_buffer((void **)(&arg), PAGE_SIZE));

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(arg));

            return retcode;
#endif
        case F_SETSIG:
            // I don't want no crazy signal.
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl,                          // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),// int fd
                                        cmd,                                                // int cmd
                                        SIGIO);                                             // long pid
            return retcode;
        case F_SETOWN:
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl,                            // int
                                        typelib_get_resource(this, NULL, RES_FILE, RF_NONE),  // int fd
                                        cmd,                                                  // int cmd
                                        typelib_get_resource(this, NULL, RES_FORK, RF_NONE)); // long pid

            return retcode;
        case F_SETFL:
            // Maybe set O_NONBLOCK
        default:
            retcode = spawn_syscall_lwp(this, &result, __NR_fcntl,                          // int
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

