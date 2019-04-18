#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Unimplemented system call.
SYSFUZZ(break, __NR_break, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gint   retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL,__NR_break);

    // These system calls always return -1 and set errno to ENOSYS.
    g_assert_cmpuint(retcode, ==, ENOSYS);

    return retcode;
}

