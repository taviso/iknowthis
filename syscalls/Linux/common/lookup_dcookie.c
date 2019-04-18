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

// Return a directory entry’s path, requires CAP_SYS_ADMIN.
// int lookup_dcookie(u64 cookie, char * buffer, size_t len);
SYSFUZZ(lookup_dcookie, __NR_lookup_dcookie, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gpointer    buffer;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_lookup_dcookie,                        // int
                                typelib_get_integer(),                                  // u32 addr_low
                                typelib_get_integer(),                                  // u32 addr_high
                                typelib_get_buffer(&buffer, PAGE_SIZE),                 // char *buffer
                                typelib_get_integer());                                 // size_t len

    // Clean up.
    typelib_clear_buffer(buffer);
    return retcode;
}

