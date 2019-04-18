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

// Manipulate the kernel’s key management facility
// long keyctl(int cmd, ...); (up to 4 arguments)
// XXX: i bet i need typelib support for those serials.
SYSFUZZ(keyctl, __NR_keyctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gint        cmd;

    cmd     =   g_random_int_range(0, 32);

    retcode = spawn_syscall_lwp(this, NULL, __NR_keyctl,                                         // key_serial_t
                                cmd,                                                             // int cmd
                                typelib_get_integer(),
                                typelib_get_integer(),
                                typelib_get_integer(),
                                typelib_get_integer());

    return retcode;
}

