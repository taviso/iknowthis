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

// Set real and/or effective user or group ID.
SYSFUZZ(setregid32, __NR_setregid32, SYS_NONE, CLONE_DEFAULT, 0)
{
	return spawn_syscall_lwp(this, NULL, __NR_setregid32,           // int
	                         typelib_get_integer(),                 // gid_t rgid
	                         typelib_get_integer());                // gid_t egid
}

