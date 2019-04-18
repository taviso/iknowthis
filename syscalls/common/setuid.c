#include <glib.h>
#include <errno.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set user identity.
// int setuid(uid_t uid);
SYSFUZZ(setuid, SYS_setuid, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gint        uid;

    uid     = typelib_get_integer();
    retcode = spawn_syscall_lwp(this, NULL, SYS_setuid,                                 // int
                                uid);                                                   // uid_t uid

    if (retcode == ESUCCESS) {
        g_assert_cmpint(uid, !=, 0);
    }

    return retcode;
}

