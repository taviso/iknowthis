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

// Give advice about file access.
//         long fadvise64_64 (int fs, loff_t offset, loff_t len, int advice,
//                            int fs, loff_t offset,
//                            loff_t len, int advice);

SYSFUZZ(fadvise64_64, __NR_fadvise64_64, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_fadvise64_64,                             // long
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // int fd
                             typelib_get_integer(),                                     // long offset
                             typelib_get_integer(),                                     // size_t len
                             typelib_get_integer());                                    // int advice
}

