#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// get descriptor table size
// int getdtablesize(void);
SYSFUZZ(getdtablesize, SYS_getdtablesize, SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS_getdtablesize);
}
