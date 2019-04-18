#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/utsname.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get name and information about current kernel.
SYSFUZZ(uname, __NR_uname, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    buf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_uname,                                     // int
                                typelib_get_buffer(&buf, sizeof(struct utsname)));          // struct utsname *buf

    typelib_clear_buffer(buf);
    return retcode;
}

