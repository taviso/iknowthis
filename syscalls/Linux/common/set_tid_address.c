#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Sets the current clear_child_tid to tidptr.
// long sys_set_tid_address (int *tidptr);
SYSFUZZ(set_tid_address, __NR_set_tid_address, SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer    tidptr;
    glong       retcode;

    // Execute System Call.
    retcode = spawn_syscall_lwp(this, NULL, __NR_set_tid_address,                           // long
                                typelib_get_buffer(&tidptr, sizeof(int)));                  // int *tidptr

    typelib_clear_buffer(tidptr);
    return retcode;
}

