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

// Reposition read/write file offset.
// int _llseek(unsigned int fd, unsigned long offset_high,
//             unsigned long offset_low, loff_t *result,
//             unsigned int whence);
SYSFUZZ(_llseek, __NR__llseek, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    result;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR__llseek,                               // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_integer(),                                  // unsigned long offset_high
                                typelib_get_integer(),                                  // unsigned long offset_low
                                typelib_get_buffer(&result, PAGE_SIZE),                 // loff_t *result
                                typelib_get_integer_range(0, 2));                       // int whence

    typelib_clear_buffer(result);

    return retcode;
}

