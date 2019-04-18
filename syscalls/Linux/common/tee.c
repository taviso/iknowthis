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

// Duplicating pipe content.
// long tee(int fd_in, int fd_out, size_t len, unsigned int flags);
SYSFUZZ(tee, __NR_tee, SYS_NONE, CLONE_DEFAULT, 1000)
{
    return spawn_syscall_lwp(this, NULL, __NR_tee,                                      // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd_in
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd_out
                             typelib_get_integer(),                                     // size_t len
                             typelib_get_integer_mask(SPLICE_F_MOVE
                                                    | SPLICE_F_NONBLOCK
                                                    | SPLICE_F_MORE
                                                    | SPLICE_F_GIFT));                  // unsigned int flags
}

