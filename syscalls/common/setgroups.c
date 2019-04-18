#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set list of supplementary group IDs.
// int setgroups(size_t size, const gid_t *list);
SYSFUZZ(setgroups, SYS_setgroups, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gpointer    list;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_setgroups,                                  // int
                                typelib_get_integer(),                                      // int size
                                typelib_get_buffer(&list, PAGE_SIZE));                      // gid_t list[]

    typelib_clear_buffer(list);

    return retcode;
}

