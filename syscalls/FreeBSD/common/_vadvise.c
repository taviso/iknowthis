#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__vadvise
# define SYS__vadvise 72
#endif

// give advice to paging system
// int vadvise(int param);
SYSFUZZ(_vadvise, SYS__vadvise, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__vadvise, typelib_get_integer());
}

