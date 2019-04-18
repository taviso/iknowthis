#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// manipulate disk quota
// int quotactl(int cmd, const char *special, int id, caddr_t addr);
SYSFUZZ(quotactl, SYS_quotactl, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gchar      *special;
    gpointer    addr;

    retcode = spawn_syscall_lwp(this, NULL, SYS_quotactl,               // int
                                typelib_get_integer(),                  // int cmd
                                typelib_get_pathname(&special),         // const char *special
                                typelib_get_integer(),                  // int id
                                typelib_get_buffer(&addr, PAGE_SIZE));  // caddr_t addr

    typelib_clear_buffer(addr);
    g_free(special);
    return retcode;
}
