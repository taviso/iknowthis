#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get real, effective and saved user/group IDs.
// int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
SYSFUZZ(getresuid, SYS_getresuid, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    ruid;
    gpointer    euid;
    gpointer    suid;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getresuid,                                          // int
                                typelib_get_buffer(&ruid, g_random_int_range(0, 8)),                // uid_t *ruid
                                typelib_get_buffer(&euid, g_random_int_range(0, 8)),                // uid_t *euid
                                typelib_get_buffer(&suid, g_random_int_range(0, 8)));               // uid_t *suid

    typelib_clear_buffer(ruid);
    typelib_clear_buffer(euid);
    typelib_clear_buffer(suid);

    return retcode;
}

