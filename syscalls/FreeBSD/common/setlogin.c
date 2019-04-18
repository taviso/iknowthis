#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set login name.
// int setlogin(char *namebuf);
SYSFUZZ(setlogin, SYS_setlogin, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    namebuf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_setlogin,                   // int
                                typelib_get_buffer(&namebuf, PAGE_SIZE));   // char *namebuf

    typelib_clear_buffer(namebuf);
    return retcode;
}
