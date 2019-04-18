#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set architecture-specific thread state.
// int arch_prctl(int code, unsigned long addr);
// int arch_prctl(int code, unsigned long *addr);
SYSFUZZ(arch_prctl, __NR_arch_prctl, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_arch_prctl,                                            // int
                                typelib_get_integer_selection(4, ARCH_SET_FS,                           // int code
                                                                 ARCH_GET_FS,
                                                                 ARCH_SET_GS,
                                                                 ARCH_GET_GS),
                                typelib_get_integer());                                                 // unsigned long addr

    return retcode;
}
