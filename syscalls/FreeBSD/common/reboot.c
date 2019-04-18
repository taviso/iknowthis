#include <glib.h>
#include <errno.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Reboot system or halt processor.
// int reboot(int howto);
SYSFUZZ(reboot, SYS_reboot, SYS_FAIL, CLONE_DEFAULT, 0)
{
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_reboot,                                 // int
                                typelib_get_integer());                                 // int howto

    return retcode;
}

