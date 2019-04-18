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

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_shm_segment(guintptr shmid)
{
    return shmctl(shmid, IPC_RMID, NULL) != -1;
}

// Allocates a shared memory segment.
// int shmget(key_t key, size_t size, int shmflg);
SYSFUZZ(shmget, __NR_shmget, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong  retcode;
    glong  shmid = -1;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, &shmid, __NR_shmget,                                                                   // int
                                      typelib_get_integer_selection(2, IPC_PRIVATE, typelib_get_integer()),                  // key_t key
                                      typelib_get_integer_range(0, PAGE_SIZE),                                               // size_t size
                                      typelib_get_integer_mask(IPC_CREAT | IPC_EXCL | SHM_HUGETLB | SHM_NORESERVE | 0777));  // int shmflg

    // Record the new shmid.
    if (retcode == ESUCCESS) {
        typelib_add_resource(this, shmid, RES_SHMID, RF_NONE, destroy_shm_segment);
    }

    return retcode;
}
