#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Add a watch to an initialized inotify instance.
// int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
SYSFUZZ(inotify_add_watch, __NR_inotify_add_watch, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    glong    retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_inotify_add_watch,                             // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),            // int fd
                                typelib_get_pathname(&pathname),                                // const char *pathname
                                typelib_get_integer());                                         // uint32_t mask
    g_free(pathname);

    return retcode;
}

