#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__getkerninfo
# define SYS__getkerninfo 63
#endif

// Get kernel info.
// int getkerninfo(int op, char *where, size_t *size, int arg);
SYSFUZZ(_getkerninfo, SYS__getkerninfo, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    where;
    gpointer    size;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS__getkerninfo,                                // int
                                typelib_get_integer(),                                       // int op
                                typelib_get_buffer(&where, PAGE_SIZE),                       // char *where
                                typelib_get_buffer(&size, sizeof(size_t)),                   // size_t *size
                                typelib_get_integer());                                      // int arg

    typelib_clear_buffer(where);
    typelib_clear_buffer(size);
    return retcode;
}

