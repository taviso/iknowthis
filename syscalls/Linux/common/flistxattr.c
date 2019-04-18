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
// int flistxattr(int fd, const char *list, size_t size);
SYSFUZZ(flistxattr, __NR_flistxattr, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    list;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_flistxattr,                            // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_buffer(&list, PAGE_SIZE),                   // const char *list
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t size

    typelib_clear_buffer(list);

    return retcode;
}

