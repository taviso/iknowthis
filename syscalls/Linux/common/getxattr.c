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

// Get extended attribute.
// int getxattr(const char *pathname, const char *name, void *value, size_t size);
SYSFUZZ(getxattr, __NR_getxattr, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gpointer    name;
    gpointer    value;
    gchar      *pathname;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_getxattr,                              // int
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_buffer(&name, PAGE_SIZE),                   // const char *name
                                typelib_get_buffer(&value, PAGE_SIZE),                  // const void *value
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t size;

    typelib_clear_buffer(name);
    typelib_clear_buffer(value);
    g_free(pathname);

    return retcode;
}

