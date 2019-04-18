#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__gethostname
# define SYS__gethostname 87
#endif

// Obsolete
SYSFUZZ(_gethostname, SYS__gethostname, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__gethostname);
}
