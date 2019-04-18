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

// Semaphore operations.
// int semop(int semid, struct sembuf *sops, unsigned nsops);
SYSFUZZ(semop, __NR_semop, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong  retcode;
    gpointer sops;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_semop,                                         // int
                                      typelib_get_resource(this, NULL, RES_SEMID, RF_NONE),     // int semid
                                      typelib_get_buffer(&sops, PAGE_SIZE),                     // struct sembuf *sops
                                      typelib_get_integer_range(0, 1024));                      // unsigned nsops.

    typelib_clear_buffer(sops);
    return retcode;
}
