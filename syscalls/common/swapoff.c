#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Start/stop swapping to file/device.
// int swapoff(const char *path);
SYSFUZZ(swapoff, SYS_swapoff, SYS_FAIL | SYS_BORING, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gchar      *path;

    retcode = syscall_fast(SYS_swapoff, typelib_get_pathname(&path));           // const char *path

    g_free(path);
    return retcode;
}

