#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get user identity.
// uid_t getuid(void);
SYSFUZZ(getuid, SYS_getuid, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getuid);                            // uid_t
}

