#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// abort process with diagnostics
// void abort2(const char *why, int nargs, void **args);
SYSFUZZ(abort2, SYS_abort2, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    why;
    gpointer    args;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_abort2,                     // int
                                typelib_get_buffer(&why, PAGE_SIZE),        // char *name
                                typelib_get_integer(),                      // int nargs
                                typelib_get_buffer(&args, PAGE_SIZE));      // void **args

    typelib_clear_buffer(why);
    typelib_clear_buffer(args);
    return retcode;
}
