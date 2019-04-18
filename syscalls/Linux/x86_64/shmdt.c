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

// Shared memory operations.
// int shmdt(const void *shmaddr);
SYSFUZZ(shmdt, __NR_shmdt, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    guintptr    address;
    gsize       size;

    typelib_get_vma(this, &address, &size);

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_shmdt,                                          // int
                                      address);                                                  // const void *shmaddr

    // If that worked, then this vma is stale.
    if (retcode == ESUCCESS) {
        typelib_vma_stale(this, address);
    }

    return retcode;
}
