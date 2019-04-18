#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__sethostname
# define SYS__sethostname 88
#endif

// Obsolete
SYSFUZZ(_sethostname, SYS__sethostname, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__sethostname);
}
