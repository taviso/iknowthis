#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__vhangup
# define SYS__vhangup 76
#endif

// Obsolete
SYSFUZZ(_vhangup, SYS__vhangup, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__vhangup);
}
