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

// Get or set ldt.
// int mprotect(const void *addr, size_t len, int prot);
SYSFUZZ(modify_ldt, __NR_modify_ldt, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    ptr;
    glong       retcode;

    retcode = syscall_fast(__NR_modify_ldt,                                                 // int
                           typelib_get_integer_range(0, 1),                                 // int func
                           typelib_get_buffer(&ptr, g_random_int_range(0, PAGE_SIZE)),      // void *ptr
                           typelib_get_integer());                                          // unsigned long bytecount

    typelib_clear_buffer(ptr);

    return retcode;
}

