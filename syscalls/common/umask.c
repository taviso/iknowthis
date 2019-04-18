#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set file mode creation mask.
SYSFUZZ(umask, SYS_umask, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_umask, typelib_get_integer());
}

