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

// Callback for typelib_add_resource().
static gboolean destroy_message_queue(guintptr msgqid)
{
     struct msqid_ds buf;

     return msgctl(msgqid, IPC_RMID, &buf) != -1;
}

// Get a message queue identifier.
// int msgget(key_t key, int msgflg);
SYSFUZZ(msgget, __NR_msgget, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong   retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_msgget,                                                // int
                                typelib_get_integer_selection(2, IPC_PRIVATE, typelib_get_integer()),   // key_t key
                                typelib_get_integer());                                                 // int msgflg

    if (retcode == ESUCCESS) {
        typelib_add_resource(this, retcode, RES_MSGQ, RF_NONE, destroy_message_queue);
    }

    return retcode;
}
