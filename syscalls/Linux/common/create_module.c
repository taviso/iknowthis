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

// Create a loadable module entry.
// caddr_t create_module(const char *name, size_t size);
SYSFUZZ(create_module, __NR_create_module, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer    name;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_create_module,                             // caddr_t
                                typelib_get_buffer(&name, g_random_int_range(0, 0x1000)),   // const char *name
                                typelib_get_integer());                                     // size_t siz

    typelib_clear_buffer(name);

    return retcode;
}

