#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_semaphore(guintptr semid)
{
    return semctl(semid, -1, IPC_RMID) != -1;
}

// Get a semaphore set identifier.
// int semget(key_t key, int nsems, int semflg);
SYSFUZZ(semget, __NR_semget, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong  retcode;
    glong  semid = -1;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, &semid, __NR_semget,                                                                   // int
                                      typelib_get_integer_selection(2, IPC_PRIVATE, typelib_get_integer()),                  // key_t key
                                      typelib_get_integer_range(0, 256),                                                     // int nsems
                                      typelib_get_integer_mask(IPC_CREAT | IPC_EXCL | 0777));                                // int semflg

    // Record the new shmid.
    if (retcode == ESUCCESS) {
        typelib_add_resource(this, semid, RES_SEMID, RF_NONE, destroy_semaphore);
    }

    return retcode;
}
