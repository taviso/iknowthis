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

// Sync a file segment with disk.
// void sync_file_range(int fd, off64_t offset, off64_t nbytes,
//                      unsigned int flags);
// long sys32_sync_file_range(int fd, unsigned off_low, unsigned off_hi,
//                            unsigned n_low, unsigned n_hi,  int flags);
SYSFUZZ(sync_file_range, __NR_sync_file_range, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_sync_file_range,                        // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),     // int fd
                             typelib_get_integer(),                                   // unsigned off_low
                             typelib_get_integer(),                                   // unsigned off_high
                             typelib_get_integer(),                                   // unsigned n_low
                             typelib_get_integer(),                                   // unsigned n_high
                             typelib_get_integer_mask(SYNC_FILE_RANGE_WAIT_BEFORE 
                                                      | SYNC_FILE_RANGE_WRITE 
                                                      | SYNC_FILE_RANGE_WAIT_AFTER)); // int flags;
}

