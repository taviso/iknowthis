#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// kernel environment
// int kenv(int action, const char *name, char *value, int len);
SYSFUZZ(kenv, SYS_kenv, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    name;
    gpointer    value;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_kenv,                       // int
                                typelib_get_integer(),                      // int action
                                typelib_get_buffer(&name, PAGE_SIZE),       // char *name
                                typelib_get_buffer(&value, PAGE_SIZE),      // char *value
                                typelib_get_integer());                     // int len

    typelib_clear_buffer(name);
    typelib_clear_buffer(value);
    return retcode;
}
