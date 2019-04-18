#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS__getpagesize
# define SYS__getpagesize 64
#endif

// get system page size
// int getpagesize(void);
SYSFUZZ(_getpagesize, SYS__getpagesize, SYS_BORING, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, SYS__getpagesize);
}

