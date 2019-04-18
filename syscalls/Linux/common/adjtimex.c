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

// Tune kernel clock.
// int adjtimex(struct timex *buf);
SYSFUZZ(adjtimex, __NR_adjtimex, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    buf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_adjtimex,                                          // int
                                typelib_get_buffer(&buf, g_random_int_range(0, PAGE_SIZE)));        // struct timex *buf

    typelib_clear_buffer(buf);

    return retcode;
}

