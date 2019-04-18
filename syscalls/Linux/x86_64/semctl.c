#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// I don't know how to query this at runtime.
#define SEMMSL 32768

// Semaphore control operations.
// int semctl(int semid, int semnum, int cmd, ...);
SYSFUZZ(semctl, __NR_semctl, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gint        cmd     = -1;
    gboolean    ptr     = false;
    gpointer    un      = NULL;

    // Choose a semaphore command.
    cmd = typelib_get_integer_selection(13, IPC_STAT,
                                            IPC_SET,
                                            IPC_RMID,
                                            IPC_INFO,
                                            SEM_INFO,
                                            SEM_STAT,
                                            GETALL,
                                            GETNCNT,
                                            GETPID,
                                            GETVAL,
                                            GETZCNT,
                                            SETALL,
                                            SETVAL);

    switch (cmd) {
        case IPC_STAT:
        case IPC_SET:
        case IPC_INFO:
        case GETALL:
        case SETALL:
        default:
            // Pointer required.
            typelib_get_buffer(&un, PAGE_SIZE);

            // Remember that we need to free it.
            ptr = true;
            break;
        // XXX FIXME, not everything should be pointer.
    }

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_semctl,                                        // int
                                      typelib_get_resource(this, NULL, RES_SEMID, RF_NONE),     // int semid
                                      typelib_get_integer_range(0, SEMMSL),                     // int semnum
                                      cmd,                                                      // int cmd
                                      un);                                                      // union semun un


    if (ptr) {
        typelib_clear_buffer(un);
    }

    return retcode;
}
