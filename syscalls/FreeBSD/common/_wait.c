#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__wait
# define SYS__wait 84
#endif

// Obsolete
// int wait(void);
SYSFUZZ(_wait, SYS__wait, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__wait);
}
