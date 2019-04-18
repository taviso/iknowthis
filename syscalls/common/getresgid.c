#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get real, effective and saved user/group IDs.
// int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
SYSFUZZ(getresgid, SYS_getresgid, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    rgid;
    gpointer    egid;
    gpointer    sgid;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getresgid,                                          // int
                                typelib_get_buffer(&rgid, g_random_int_range(0, 8)),                // uid_t *rgid
                                typelib_get_buffer(&egid, g_random_int_range(0, 8)),                // uid_t *egid
                                typelib_get_buffer(&sgid, g_random_int_range(0, 8)));               // uid_t *sgid

    typelib_clear_buffer(rgid);
    typelib_clear_buffer(egid);
    typelib_clear_buffer(sgid);

    return retcode;
}

