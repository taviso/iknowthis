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

// Get current working directory.
// long getcwd(char *buf, unsigned long size);
SYSFUZZ(getcwd, __NR_getcwd, SYS_NONE, CLONE_DEFAULT, 0)
{
	glong       retcode;
	gpointer    buf;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_getcwd,                                            // long
                                typelib_get_buffer(&buf, g_random_int_range(0, PAGE_SIZE)),         // void *buf
                                typelib_get_integer());                                             // size_t count

    // Clean up.
    typelib_clear_buffer(buf);

    return retcode;
}
