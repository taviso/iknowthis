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

// This system call was removed in Linux 2.6.

// Retrieve exported kernel and module symbols.
// int get_kernel_syms(struct kernel_sym *table);
SYSFUZZ(get_kernel_syms, __NR_get_kernel_syms, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer    table;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_get_kernel_syms,
                                typelib_get_buffer(&table, g_random_int_range(0, PAGE_SIZE)));  // const char *name

    typelib_clear_buffer(table);

#ifndef __x86_64__
    g_assert_cmpint(retcode, ==, ENOSYS);
#endif

    return retcode;
}

