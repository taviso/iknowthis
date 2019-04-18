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

// Delete a loadable module entry.
// int delete_module(const char *name);
SYSFUZZ(delete_module, __NR_delete_module, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    gpointer    name;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_delete_module,                             // caddr_t
                                typelib_get_buffer(&name, PAGE_SIZE));                      // const char *name

    typelib_clear_buffer(name);

    return retcode;
}

