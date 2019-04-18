#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// XXX: This is ugly.

struct io_iocb_common {
    void                *buf;
    unsigned int         __pad1;
    long unsigned int    nbytes;
    unsigned int         __pad2;
    long long int        offset;
    long long int        __pad3;
    unsigned int         flags;
    unsigned int         resfd;
};

struct iocb {
    void                *data;
    unsigned int         __pad1;
    unsigned int         key;
    unsigned int         __pad2;
    short int            aio_lio_opcode;
    short int            aio_reqprio;
    int                  aio_fildes;
    union {
        struct io_iocb_common c;
        // struct io_iocb_vector v;
        // struct io_iocb_poll poll;
        // struct io_iocb_sockaddr saddr;
    } u;
};

gboolean destroy_iocb_callback(guintptr callback)
{
    struct iocb *iocb = GUINT_TO_POINTER(callback);

    typelib_clear_buffer(iocb->u.c.buf);
    typelib_clear_buffer(iocb);
    return true;
}

// Submit asynchronous I/O blocks for processing
// long io_submit (aio_context_t ctx_id, long nr, struct iocb **iocbpp);
#if defined(__x86_64__)
SYSFUZZ(io_submit, __NR_io_submit, SYS_DISABLED, CLONE_DEFAULT, 1000)
#else
SYSFUZZ(io_submit, __NR_io_submit, SYS_NONE, CLONE_DEFAULT, 1000)
#endif
{
    glong           retcode;
    struct iocb    *iocb;
    glong           num;
    guintptr        ctx;

    // io_submit() is very fussy about this structure.
    ctx                     = typelib_get_resource(this, NULL, RES_AIOCTX, RF_NONE);
    iocb                    = typelib_get_buffer(NULL, sizeof *iocb);
    iocb->data              = (typeof(iocb->data)) (long) typelib_get_integer_selection(1, 0);
    iocb->key               = typelib_get_integer_selection(1, 0);
    iocb->__pad1            = typelib_get_integer_selection(1, 0);
    iocb->__pad2            = typelib_get_integer_selection(1, 0);
    iocb->aio_lio_opcode    = typelib_get_integer_range(0, 8);
    iocb->aio_fildes        = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);
    iocb->u.c.buf           = typelib_get_buffer(NULL, PAGE_SIZE);
    iocb->u.c.nbytes        = typelib_get_integer_range(0, PAGE_SIZE);
    iocb->u.c.__pad1        = typelib_get_integer_selection(1, 0);
    iocb->u.c.__pad2        = typelib_get_integer_selection(1, 0);
    iocb->u.c.__pad3        = typelib_get_integer_selection(1, 0);
    iocb->u.c.flags         = typelib_get_integer();
    iocb->u.c.resfd         = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);

    retcode = spawn_syscall_lwp(this, &num, __NR_io_submit,                             // long
                                typelib_get_resource(this, NULL, RES_AIOCTX, RF_NONE),  // aio_context_t ctx_id
                                typelib_get_integer_selection(1, 1),                    // long nr
                                &iocb);                                                 // struct iocb **iocbpp

    if (retcode == ESUCCESS && num != 0) {
        g_assert_cmpint(num, ==, 1);

        typelib_add_resource(this, GPOINTER_TO_UINT(iocb), RES_AIOCB, RF_NONE, destroy_iocb_callback);
    } else {
        destroy_iocb_callback(GPOINTER_TO_UINT(iocb));
    }

    return retcode;
}

