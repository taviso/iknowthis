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

// Set group identity used for file system checks.
// int setfsgid(uid_t fsgid);
// XXX: Bizarrely, setfsgid never returns any error.
SYSFUZZ(setfsgid, __NR_setfsgid, SYS_VOID, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_setfsgid,                                                 // int
                             typelib_get_integer());                                                    // uid_t fsgid
}

