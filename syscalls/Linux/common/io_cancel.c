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

// Cancel an outstanding asynchronous I/O operation
// long io_cancel (aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
SYSFUZZ(io_cancel, __NR_io_cancel, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    iocb        = NULL;
    gpointer    result      = NULL;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_io_cancel,                                         // long
                                typelib_get_resource(this, NULL, RES_AIOCTX, RF_NONE),              // aio_context_t ctx_id
                                typelib_get_resource(this, VU(&iocb), RES_AIOCB, RF_TAKEOWNERSHIP), // struct iocb *iocb
                                typelib_get_buffer(&result, PAGE_SIZE));                            // struct io_event *result

    // Clean up.
    typelib_clear_buffer(iocb);
    typelib_clear_buffer(result);

    return retcode;
}
