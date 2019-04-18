#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"


// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Create pipe.
// int pipe2(int pipefd[2], int flags);
SYSFUZZ(pipe2, __NR_pipe2, SYS_BORING, CLONE_DEFAULT, 0)
{
    gint    pipefd[2];
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_pipe2,                                             // int
                                pipefd,                                                             // int pipefd[2]
                                typelib_get_integer_mask(O_NONBLOCK | O_CLOEXEC));                  // int flags

    if (retcode == ESUCCESS) {
        // As nothing can go wrong with pipe, it will saturate all my available
        // fd slots very quickly, so only add them occassionally.
        if (g_random_int_range(0, 512)) {
            close(pipefd[0]);
            close(pipefd[1]);
        } else {
            typelib_add_resource(this, pipefd[0], RES_FILE, RF_NONE, destroy_open_file);
            typelib_add_resource(this, pipefd[1], RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    return retcode;
}
