#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_forked_process(guintptr pid)
{
    g_assert_cmpuint(pid, >, 1);

    kill(pid, SIGKILL);

    waitpid(pid, NULL, __WALL);

    return true;
}

// Create a child process.
SYSFUZZ(clone, __NR_clone, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    pid_t       pid = -1;
    gpointer    arg1;
    gpointer    arg2;
    gpointer    arg3;
    gpointer    arg4;

    arg1    = typelib_get_buffer(NULL, PAGE_SIZE);
    arg2    = typelib_get_buffer(NULL, PAGE_SIZE);
    arg3    = typelib_get_buffer(NULL, PAGE_SIZE);
    arg4    = typelib_get_buffer(NULL, PAGE_SIZE);

    // I think the lwp syscall code may not handle this well.
    retcode = syscall_fast_ret(&pid, __NR_clone,
                                (typelib_get_integer() & ~0xff),    // Mask to prevent requesting SIGKILL or similar.
                                g_random_boolean() ? arg1 : NULL,
                                g_random_boolean() ? arg2 : NULL,
                                g_random_boolean() ? arg3 : NULL,
                                g_random_boolean() ? arg4 : NULL);

    // Determine what happened.
    switch (pid) {
        case  0: // Make sure this wouldnt put us over process quota.
                 if (increment_process_count() > MAX_PROCESS_NUM) {

                    // Nested too deeply, terminate self.
                    while (true) {
                        syscall(__NR_exit, 0);
                        // Note: This can really fail. Spin here until I'm reaped.
                        pause();
                    }
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

    typelib_clear_buffer(arg1);
    typelib_clear_buffer(arg2);
    typelib_clear_buffer(arg3);
    typelib_clear_buffer(arg4);
    return retcode;
}

