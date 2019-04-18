#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set user identity used for file system checks.
// int setfsuid(uid_t fsuid);

// XXX: Bizarrely, setfsuid() never returns error, even if it failed.
SYSFUZZ(setfsuid, __NR_setfsuid, SYS_VOID, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_setfsuid,                                                 // int
                             typelib_get_integer());                                                    // uid_t fsuid
}

