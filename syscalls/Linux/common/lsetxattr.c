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

// Set extended attribute.
// int lsetxattr(const char *pathname, const char  *name, const void *value, size_t size, int flags);
SYSFUZZ(lsetxattr, __NR_lsetxattr, SYS_NONE, CLONE_DEFAULT, 0)
{
	glong       retcode;
    gchar      *pathname;
    gpointer    name;
    gpointer    value;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_lsetxattr,                             // int
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_buffer(&name, g_random_int_range(0, 8192)), // const char *name
                                typelib_get_buffer(&value, g_random_int_range(0, 8192)),// const void *value
                                typelib_get_integer(),                                  // size_t size
                                typelib_get_integer());                                 // int flags

    // Clean up.
    g_free(pathname);
    typelib_clear_buffer(name);
    typelib_clear_buffer(value);

    return retcode;
}

