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
#include "compat.h"

// Shared memory operations.
// void *shmat(int shmid, const void *shmaddr, int shmflg);
SYSFUZZ(shmat, __NR_shmat, SYS_DISABLED, CLONE_DEFAULT, 1000)
{
    glong   retcode;
    glong   shmid = -1;
    glong   result;

    // Fetch a shmid to use.
    shmid = typelib_get_resource(this, NULL, RES_SHMID, RF_NONE);

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, &result, __NR_shmat,                                                                 // int
                                      shmid,                                                                               // int shmid
                                      typelib_get_integer_selection(2, NULL, typelib_get_integer()),                       // const void *shmaddr
                                      typelib_get_integer_mask(SHM_RND
                                                                | SHM_RDONLY
                                                                | SHM_REMAP
                                                                | SHM_EXEC));                                              // int shmflag

    // Record the result as a new vma.
    if (retcode != -1) {
        struct shmid_ds buf = {
            .shm_segsz  = PAGE_SIZE,
        };

        // Query the segment size, note that this is not particularly important
        // as shmdt doesnt require a size like munmap, so I'll set the default
        // to PAGE_SIZE, the smallest possible size.
        if (shmctl(shmid, IPC_STAT, &buf) == -1) {
            g_debug("shmctl() after a successful shmat() failed, %m");
        }

        // Record.
        typelib_vma_new(this, result, buf.shm_segsz, VMA_SHM);
    }

    return retcode;
}
