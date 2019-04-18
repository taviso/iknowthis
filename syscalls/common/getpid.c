#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get process identification.
// pid_t getpid(void);
SYSFUZZ(getpid, SYS_getpid, SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getpid);
}
