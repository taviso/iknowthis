#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change segment size.
// int sbrk(int incr);
SYSFUZZ(sbrk, SYS_sbrk, SYS_DISABLED, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_sbrk, typelib_get_integer());
}

