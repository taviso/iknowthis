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

// Set time.
// int stime(time_t *t);
SYSFUZZ(stime, __NR_stime, SYS_FAIL | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gpointer   t;
    gint       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_stime,                                // int
                                typelib_get_buffer(&t, PAGE_SIZE));                    // time_t *t

    typelib_clear_buffer(t);

    return retcode;
}

