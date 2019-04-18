#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Read asynchronous I/O events from the completion queue.
// long io_getevents (aio_context_t ctx_id, long min_nr, long nr,
//                    struct io_event *events, struct timespec *timeout);
SYSFUZZ(io_getevents, __NR_io_getevents, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    events;
    gpointer    timeout;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_io_getevents,                              // long
                                typelib_get_resource(this, NULL, RES_AIOCTX, RF_NONE),      // aio_context_t ctx_id
                                typelib_get_integer(),                                      // long min_nr
                                typelib_get_integer(),                                      // long nr
                                typelib_get_buffer(&events, PAGE_SIZE),                     // struct io_event *events
                                typelib_get_buffer(&timeout, PAGE_SIZE));                   // struct timespec *timeout

    // Clean up.
    typelib_clear_buffer(events);
    typelib_clear_buffer(timeout);

    return retcode;
}

