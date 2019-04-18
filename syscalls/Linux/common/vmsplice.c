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

// Splice user pages into a pipe.
// ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags);
// XXX: make an iovec typelib
SYSFUZZ(vmsplice, __NR_vmsplice, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    iov;
    gint        size;

    typelib_get_iovec(&iov, &size, IOV_NONE);

    retcode = spawn_syscall_lwp(this, NULL, __NR_vmsplice,                              // long
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                iov,                                                    // const struct iovec *iov
                                size,                                                   // unsigned long nrsegs
                                typelib_get_integer());                                 // unsigned int flags

    typelib_clear_iovec(iov, size, IOV_NONE);
    return retcode;
}

