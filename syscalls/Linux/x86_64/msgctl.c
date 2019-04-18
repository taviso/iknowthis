#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Message control operations.
// int msgctl(int msqid, int cmd, struct msqid_ds *buf);
SYSFUZZ(msgctl, __NR_msgctl, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    buf;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_msgctl,                                    // int
                                typelib_get_resource(this, NULL, RES_MSGQ, RF_NONE),        // int msqid
                                typelib_get_integer(),                                      // int cmd
                                typelib_get_buffer(&buf, PAGE_SIZE));                       // struct msqid_ds *buf

    typelib_clear_buffer(buf);

    return retcode;
}
