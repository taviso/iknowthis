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

// Destroy an asynchronous I/O context
// int io_destroy (io_context_t ctx);
SYSFUZZ(io_destroy, __NR_io_destroy, SYS_NONE, CLONE_DEFAULT, 1000)
{
    return spawn_syscall_lwp(this, NULL, __NR_io_destroy,                                      // int
                             typelib_get_resource(this, NULL, RES_AIOCTX, RF_TAKEOWNERSHIP));  // io_context_t *ctxp
}

