#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Commit buffer cache to disk.
// void sync(void);
SYSFUZZ(sync, SYS_sync, SYS_VOID | SYS_SAFE | SYS_DISABLED, CLONE_DEFAULT, 0)
{
    // Disabled as it's slow and trivial.
    return spawn_syscall_lwp(this, NULL, SYS_sync);                                                // void
}
