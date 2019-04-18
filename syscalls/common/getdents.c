#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get directory entries.
// int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
SYSFUZZ(getdents, SYS_getdents, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    dirp;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_getdents,                                   // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // int fd
                                typelib_get_buffer(&dirp, PAGE_SIZE),                       // struct linux_dirent *dirp
                                typelib_get_integer_range(0, PAGE_SIZE));                   // unsigned int count

    typelib_clear_buffer(dirp);

    return retcode;
}
