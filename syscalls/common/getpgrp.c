#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set/get process group.
// pid_t getpgrp(psid_t pid);
SYSFUZZ(getpgrp, SYS_getpgrp, SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getpgrp, typelib_get_resource(this, NULL, RES_FORK, RF_NONE));   // pid_t
}

