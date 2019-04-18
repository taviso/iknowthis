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

// Reboot or enable/disable Ctrl-Alt-Del
SYSFUZZ(reboot, __NR_reboot, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
	gpointer    arg;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_reboot,                                     // int
                                LINUX_REBOOT_MAGIC1,                                         // int magic
                                LINUX_REBOOT_MAGIC2,                                         // int magic2
                                typelib_get_integer(),                                       // int cmd
                                typelib_get_buffer(&arg, PAGE_SIZE));                        // void *arg

    typelib_clear_buffer(arg);

    return retcode;
}

