#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/mman.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef __WALL
# define __WALL 0
#endif

// Callback for typelib_add_resource().
static gboolean destroy_forked_process(guintptr pid)
{
    g_assert_cmpuint(pid, >, 1);

    // Terminate it.
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        g_message("destroy_forked_process failed to kill forked process %lu, %m", pid);
    }

    // Wait for it to stop.
    if (waitpid(pid, NULL, __WALL) != pid && errno != ECHILD) {
        g_message("destroy_forked_process failed to wait for forked process %lu, %m", pid);
    }

    return true;
}

// Create a child process.
// pid_t fork(void);
SYSFUZZ(fork, SYS_fork, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong           retcode;
    pid_t           pid = -1;

    // I think the lwp syscall code may not handle this well, luckily fork() is
    // simple enough that I can handle it here.
    retcode = syscall_fast_ret(&pid, SYS_fork);

    // Determine what happened.
    switch (pid) {
        case  0: // Make sure this wouldnt put us over process quota.
                 if (increment_process_count() > MAX_PROCESS_NUM) {
                    // Terminate self.
                    _exit(0);

                    // Shouldn't continue.
                    g_assert_not_reached();
                 }

                 // Mangle prng state.
                 g_random_set_seed(time(0) ^ getpid());

                 // Continue fuzzing.
                 break;

        // Fork failed, just return error.
        case -1: break;

        // Parent process, add the child.
        default: typelib_add_resource(this, pid, RES_FORK, RF_NONE, destroy_forked_process);
                 break;
    }

    return retcode;
}
