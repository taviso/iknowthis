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

// Wait for process to change state.
// int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
SYSFUZZ(waitid, __NR_waitid, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer     infop;
    glong        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_waitid,                                                                // pid_t
                                typelib_get_integer_selection(3, P_PID, P_PGID, P_ALL),                                 // idtype_t idtype
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),                                    // pid_t pid
                                typelib_get_buffer(&infop, PAGE_SIZE),                                                  // int *status
                                typelib_get_integer_mask(WNOHANG|WUNTRACED|WCONTINUED|__WNOTHREAD|__WCLONE|__WALL));    // int options

    typelib_clear_buffer(infop);

    return retcode;
}

