#include <glib.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get user identity.
// uid_t geteuid(void);
SYSFUZZ(geteuid, SYS_geteuid, SYS_SAFE | SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_geteuid);     // void
}

