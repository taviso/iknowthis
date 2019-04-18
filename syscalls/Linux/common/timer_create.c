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

// Create a POSIX.1b interval timer clock
// long sys_timer_create (clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id);
SYSFUZZ(timer_create, __NR_timer_create, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    timer_event_spec;
    gpointer    created_timer_id;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_timer_create,
                                typelib_get_integer_range(0, 6),                                        // clockid_t which_clock,
                                typelib_get_buffer(&timer_event_spec, PAGE_SIZE),                       // struct sigevent *timer_event_spec,
                                typelib_get_buffer(&created_timer_id, PAGE_SIZE));                      // timer_t *created_timer_id

    typelib_clear_buffer(timer_event_spec);
    typelib_clear_buffer(created_timer_id);

    return retcode;
}

