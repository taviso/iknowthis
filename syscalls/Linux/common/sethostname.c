#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set hostname.
// int sethostname(const char *name, size_t len);
SYSFUZZ(sethostname, __NR_sethostname, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer    name;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_sethostname,                            // int
                                typelib_get_buffer(&name, g_random_int_range(0, 8192)),  // const char *name
                                typelib_get_integer());                                  // size_t len

    typelib_clear_buffer(name);
    return retcode;
}

