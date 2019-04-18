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

// Enter virtual 8086 mode.
// int vm86(unsigned long fn, struct vm86plus_struct *v86);
SYSFUZZ(vm86, __NR_vm86, SYS_NONE, CLONE_FORK, 1000)
{
    gpointer    v86;
    gint        retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_vm86,                                      // int
                                typelib_get_integer_range(0, 6),                            // unsigned long fn
                                typelib_get_buffer(&v86, PAGE_SIZE));                       // struct vm86plus_struct *v86

    typelib_clear_buffer(v86);

    return retcode;
}

