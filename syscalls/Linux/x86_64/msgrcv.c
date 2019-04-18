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
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Message operations.
// ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
SYSFUZZ(msgrcv, __NR_msgrcv, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    msgp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_msgrcv,                                            // ssize_t
                                typelib_get_resource(this, NULL, RES_MSGQ, RF_NONE),                // int msqid
                                typelib_get_buffer(&msgp, PAGE_SIZE),                               // void *msgp
                                typelib_get_integer_range(0, PAGE_SIZE),                            // size_t msgsz
                                typelib_get_integer_selection(3, 0,
                                                                 typelib_get_integer(),
                                                                -typelib_get_integer()),            // long msgtyp
                                typelib_get_integer_mask(IPC_NOWAIT | MSG_EXCEPT | MSG_NOERROR));   // int msgflg

    typelib_clear_buffer(msgp);

    return retcode;
}
