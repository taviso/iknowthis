#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__vwrite
# define SYS__vwrite 68
#endif

// Obsolete.
SYSFUZZ(_vwrite, SYS__vwrite, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__vwrite);
}
