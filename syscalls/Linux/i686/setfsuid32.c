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
SYSFUZZ(setfsuid32, __NR_setfsuid32, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_setfsuid32,                                               // int
	                         typelib_get_integer());                                                    // uid_t fsuid
}

