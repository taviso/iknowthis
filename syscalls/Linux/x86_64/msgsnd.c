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

// Message operations.
// int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
SYSFUZZ(msgsnd, __NR_msgsnd, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    msgp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_msgsnd,                                    // int
                                typelib_get_resource(this, NULL, RES_MSGQ, RF_NONE),        // int msqid
                                typelib_get_buffer(&msgp, PAGE_SIZE),                       // const void *msgp
                                typelib_get_integer_range(0, PAGE_SIZE),                    // size_t msgsz
                                typelib_get_integer());                                     // int msgflg

    typelib_clear_buffer(msgp);

    return retcode;
}
