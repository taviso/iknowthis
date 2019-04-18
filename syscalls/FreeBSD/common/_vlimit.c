#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__vlimit
# define SYS__vlimit 77
#endif

// Obsolete
SYSFUZZ(_vlimit, SYS__vlimit, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__vlimit);
}
