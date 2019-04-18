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
// int fgetxattr(int fd, const char *name, void *value, size_t size);
SYSFUZZ(fgetxattr, __NR_fgetxattr, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gpointer    name;
    gpointer    value;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_fgetxattr,                             // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),    // int fd
                                typelib_get_buffer(&name, PAGE_SIZE),                   // const char *name
                                typelib_get_buffer(&value, PAGE_SIZE),                  // const void *value
                                typelib_get_integer_range(0, PAGE_SIZE));               // size_t size

    typelib_clear_buffer(name);
    typelib_clear_buffer(value);

    return retcode;
}

