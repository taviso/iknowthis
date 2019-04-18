#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get login name.
// int getlogin(char *namebuf, u_int  len);
SYSFUZZ(getlogin, SYS_getlogin, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    namebuf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getlogin,                   // int
                                typelib_get_buffer(&namebuf, PAGE_SIZE),    // char *namebuf
                                typelib_get_integer());                     // u_int  len

    typelib_clear_buffer(namebuf);
    return retcode;
}
