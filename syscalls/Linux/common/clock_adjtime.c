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

#ifndef __NR_clock_adjtime
# if defined(__i386__)
#  define __NR_clock_adjtime 343
# elif defined(__x86_64__)
#  define __NR_clock_adjtime 305
# else
#  error please define __NR_clock_adjtime for your architecture
# endif
#endif

// Tune kernel clock.
// int clock_adjtime(const clockid_t which_clock, struct timex *utx);
SYSFUZZ(clock_adjtime, __NR_clock_adjtime, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    buf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_clock_adjtime,                                     // int
                                g_random_boolean() ? + g_random_int_range(0, 16)
                                                   : - g_random_int_range(0, 16),                   // clockid_t clock
                                typelib_get_buffer(&buf, g_random_int_range(0, PAGE_SIZE)));        // struct timex *buf

    typelib_clear_buffer(buf);
    return retcode;
}

