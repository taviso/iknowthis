#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Return date and time, no longer implemented as a system call.
// int ftime(struct timeb *tp);
SYSFUZZ(ftime, __NR_ftime, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer   tp;
    gint       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_ftime,                                 // int
                                typelib_get_buffer(&tp, g_random_int_range(0, 32)));    // struct timeb *tp

    typelib_clear_buffer(tp);

    return retcode;
}
