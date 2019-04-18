#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Change data segment size.
// int break(void *addr);
SYSFUZZ(brk, SYS_break, SYS_DISABLED, CLONE_FORK, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_break, typelib_get_integer());
}

