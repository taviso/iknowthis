#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"
#include "resource.h"

// Wait for process to change state.
// pid_t waitpid(pid_t pid, int *status, int options);
SYSFUZZ(waitpid, __NR_waitpid, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer     status;
    gint         retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_waitpid,                                                               // pid_t
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                                    // pid_t pid
                                typelib_get_buffer(&status, PAGE_SIZE),                                                 // int *status
                                typelib_get_integer_mask(WNOHANG|WUNTRACED|WCONTINUED|__WNOTHREAD|__WCLONE|__WALL));    // int options

    // Mask is from initial check in sys_wait4() (exit.c, 2.6.25.3).
    typelib_clear_buffer(status);

    return retcode;
}

