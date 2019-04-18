#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Creates a session and sets the process group ID.
// pid_t setsid(void);
SYSFUZZ(setsid, SYS_setsid, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_setsid);               // pid_t
}

