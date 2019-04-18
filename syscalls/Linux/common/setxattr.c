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

// TODO: Add typelib support for xattrs so that I can record values seen by
//       getxattr, and return similar values. e.g. typelib_get_xattr(this).

// Set extended attribute.
// int setxattr(const char *pathname, const char  *name, const void *value, size_t size, int flags);
SYSFUZZ(setxattr, __NR_setxattr, SYS_NONE, CLONE_DEFAULT, 0)
{
	glong       retcode;
    gchar      *pathname;
    gpointer    name;
    gpointer    value;
	
    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_setxattr,                              // int
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_buffer(&name, PAGE_SIZE),                   // const char *name
                                typelib_get_buffer(&value, PAGE_SIZE),                  // const void *value
                                typelib_get_integer_range(0, PAGE_SIZE),                // size_t size
                                typelib_get_integer());                                 // int flags

    // Clean up.
    g_free(pathname);
    typelib_clear_buffer(name);
    typelib_clear_buffer(value);

    return retcode;
}

