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

#ifndef __NR_open_by_handle_at
# if defined(__i386__)
#  define __NR_open_by_handle_at 342
# elif defined(__x86_64__)
#  define __NR_open_by_handle_at 304
# else
#  error please define __NR_open_by_handle_at for your architecture
# endif
#endif

// It looks like this:
// struct file_handle {
//    guint32       handle_bytes;
//    int           handle_type;
//    unsigned char f_handle[0];
// };

// Open the file handle.
// int open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags);
SYSFUZZ(open_by_handle_at, __NR_open_by_handle_at, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer     handle;
    glong        retcode;


    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_open_by_handle_at,                                 // int
                                     typelib_get_resource(this, NULL, RES_FILE, RF_NONE),           // int dirfd
                                     typelib_get_buffer(&handle, g_random_int_range(0, PAGE_SIZE)), // struct file_handle *handle
                                     typelib_get_integer());                                        // int flags

    typelib_clear_buffer(handle);
    return retcode;
}

