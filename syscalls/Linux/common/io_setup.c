#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_io_context(guintptr ctx)
{
    return syscall(__NR_io_destroy, ctx) == ESUCCESS
        ? true
        : false;
}

// Create an asynchronous I/O context
// int io_setup (int maxevents, io_context_t *ctxp);
SYSFUZZ(io_setup, __NR_io_setup, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    guintptr    ctx;

    // Ctx must be initialised to zero before call.
    memset(&ctx, 0x00, sizeof ctx);

    // Execute systemcall.
    retcode = syscall_fast(__NR_io_setup,                                // int
                           typelib_get_integer_range(0, 0x10000),        // int maxevents (aio_max_nr sysctl)
                           &ctx);                                        // io_context_t *ctxp

    // Record the new context if that worked.
    if (retcode == ESUCCESS) {
        // This can be negative, apparently.
        // g_assert_cmpint(ctx, >, 0);
        typelib_add_resource(this, ctx, RES_AIOCTX, RF_NONE, destroy_io_context);
    }

    return retcode;
}
