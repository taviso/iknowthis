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

// Create pipe.
SYSFUZZ(pipe, SYS_pipe, SYS_BORING, CLONE_DEFAULT, 0)
{
    gint    pipefd[2];
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_pipe,                                               // int
                                pipefd);                                                            // int pipefd[2]

    if (retcode == ESUCCESS) {
        // As nothing can go wrong with pipe, it will saturate all my available
        // fd slots very quickly, so only add them occassionally.
        if (g_random_int_range(0, 1024)) {
            close(pipefd[0]);
            close(pipefd[1]);
        } else {
            typelib_add_resource(this, pipefd[0], RES_FILE, RF_NONE, destroy_open_file);
            typelib_add_resource(this, pipefd[1], RES_FILE, RF_NONE, destroy_open_file);
        }
    }

    return retcode;
}
