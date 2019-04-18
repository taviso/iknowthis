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

#if defined(__x86_64__)
# define USELIB_SYS_FLAGS SYS_FAIL | SYS_BORING | SYS_SAFE  // Not implemented on x64.
#else
# define USELIB_SYS_FLAGS SYS_NONE                          // Is still available on x32.
#endif

// Load shared library.
// int uselib(const char *library);
SYSFUZZ(uselib, __NR_uselib, USELIB_SYS_FLAGS, CLONE_FORK, 1000)
{
    gchar   *library;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_uselib,                                    // int
                                typelib_get_pathname(&library));                            // const char *library

    g_free(library);

    return retcode;
}

