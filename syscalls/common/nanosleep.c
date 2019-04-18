#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// High-resolution sleep.
// int nanosleep(const struct timespec *req, struct timespec *rem);
SYSFUZZ(nanosleep, SYS_nanosleep, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    req;
    gpointer    rem;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_nanosleep,
                                typelib_get_buffer(&req, sizeof(struct timespec)),   // const struct timespec *req
                                typelib_get_buffer(&rem, sizeof(struct timespec)));  // struct timespec *rem

    typelib_clear_buffer(req);
    typelib_clear_buffer(rem);

    return retcode;
}

