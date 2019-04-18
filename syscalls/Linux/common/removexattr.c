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

// Remove extended attribute.
// int removexattr(const char *pathname, const char *name);
SYSFUZZ(removexattr, __NR_removexattr, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gchar      *pathname;
    gpointer    name;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_removexattr,                           // int
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_buffer(&name, g_random_int_range(0, 8192)));// const char *name

    typelib_clear_buffer(name);
    g_free(pathname);

    return retcode;
}

