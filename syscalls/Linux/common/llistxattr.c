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

// List extended attributes.
// int llistxattr(const char *pathname, const char *list, size_t size);
SYSFUZZ(llistxattr, __NR_llistxattr, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gchar      *pathname;
    gpointer    list;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_llistxattr,                            // int
                                typelib_get_pathname(&pathname),                        // const char *pathname
                                typelib_get_buffer(&list, PAGE_SIZE),                   // const char *list
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t size;

    typelib_clear_buffer(list);
    g_free(pathname);

    return retcode;
}

