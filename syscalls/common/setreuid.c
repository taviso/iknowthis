#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set real and/or effective user or group ID.
SYSFUZZ(setreuid, SYS_setreuid, SYS_NONE, CLONE_DEFAULT, 1000)
{
    return spawn_syscall_lwp(this, NULL, SYS_setreuid,                                              // int
                             typelib_get_integer_selection(2, getuid(), typelib_get_integer()),     // uid_t ruid
                             typelib_get_integer_selection(2, getuid(), typelib_get_integer()));    // uid_t euid
}

