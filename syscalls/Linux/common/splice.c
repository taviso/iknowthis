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

// Splice data to/from a pipe.
// long splice(int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len, unsigned int flags);
SYSFUZZ(splice, __NR_splice, SYS_NONE, CLONE_DEFAULT, 1000)
{
    off_t    off_in;
    off_t    off_out;
    glong    retcode;

    off_in  = typelib_get_integer_range(0, PAGE_SIZE);
    off_out = typelib_get_integer_range(0, PAGE_SIZE);

    retcode = spawn_syscall_lwp(this, NULL, __NR_splice,                                                                      // long
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                                          // int fd_in
                                &off_in,                                                                                      // off_t *off_in
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                                          // int fd_out
                                &off_out,                                                                                     // off_t *off_out
                                typelib_get_integer_range(0, PAGE_SIZE),                                                      // size_t len
                                typelib_get_integer_mask(SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT)); // unsigned int flags

    return retcode;
}

