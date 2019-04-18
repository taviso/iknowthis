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

// Remove an existing watch from an inotify instance.
// int inotify_rm_watch(int fd, uint32_t wd);
// XXX: Do i need to track watch descriptors?
SYSFUZZ(inotify_rm_watch, __NR_inotify_rm_watch, SYS_NONE, CLONE_DEFAULT, 0)
{
    return spawn_syscall_lwp(this, NULL, __NR_inotify_rm_watch,                                 // int
                             typelib_get_resource(this, NULL, RES_FILE, RF_NONE),               // int fd
                             typelib_get_integer());                                            // uint32_t wd
}

