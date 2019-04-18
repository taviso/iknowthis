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

// Wait for signal.
// int pause(void);
SYSFUZZ(pause, __NR_pause, SYS_FAIL | SYS_BORING | SYS_DISABLED, CLONE_DEFAULT, 100)
{
    gint retcode = spawn_syscall_lwp(this, NULL, __NR_pause);

    g_assert_cmpint(retcode, ==, ETIMEOUT);

    return retcode;
}

