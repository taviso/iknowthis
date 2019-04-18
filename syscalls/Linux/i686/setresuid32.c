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

// Set real, effective and saved user or group ID.
// int setresuid(uid_t ruid, uid_t euid, uid_t suid);
SYSFUZZ(setresuid32, __NR_setresuid32, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_setresuid32,                                           // int
	                         typelib_get_integer(),                                                  // uid_t ruid
	                         typelib_get_integer(),                                                  // uid_t euid
	                         typelib_get_integer());                                                 // uid_t suid
}

