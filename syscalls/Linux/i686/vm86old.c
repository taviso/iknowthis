#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// This fuzzer is expected to crash.

// Enter virtual 8086 mode.
// int vm86old(struct vm86_struct *info);
SYSFUZZ(vm86old, __NR_vm86old, SYS_NONE, CLONE_FORK, 100)
{
    gpointer    info;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_vm86old,                                   // int
                                typelib_get_buffer(&info, PAGE_SIZE));                      // struct vm86_struct *info

    typelib_clear_buffer(info);

    return retcode;
}

