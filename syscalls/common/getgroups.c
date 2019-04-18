#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set list of supplementary group IDs.
// int getgroups(int gidsetlen, gid_t *gidset);
SYSFUZZ(getgroups, SYS_getgroups, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    list;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getgroups,                                  // int
                                typelib_get_integer(),                                      // int size
                                typelib_get_buffer(&list, g_random_int_range(0, 8192)));    // gid_t list[]

    typelib_clear_buffer(list);

    return retcode;
}

