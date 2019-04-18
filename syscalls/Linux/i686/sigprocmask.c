#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Examine and change blocked signals.
// XXX FIXME
SYSFUZZ(sigprocmask, __NR_sigprocmask, SYS_DISABLED, CLONE_FORK, 0)
{
	return 0;
}

