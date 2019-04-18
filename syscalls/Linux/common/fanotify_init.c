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

#ifndef __NR_fanotify_init
# if defined(__i386__)
#  define __NR_fanotify_init 338
# elif defined(__x86_64__)
#  define __NR_fanotify_init 300
# else
#  error please define __NR_fanotify_init for your architecture
# endif
#endif
#ifndef FAN_CLOEXEC
# define FAN_CLOEXEC             0x00000001
# define FAN_NONBLOCK            0x00000002
# define FAN_CLASS_NOTIF         0x00000000
# define FAN_CLASS_CONTENT       0x00000004
# define FAN_CLASS_PRE_CONTENT   0x00000008
# define FAN_ALL_CLASS_BITS      (FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT)
# define FAN_UNLIMITED_QUEUE     0x00000010
# define FAN_UNLIMITED_MARKS     0x00000020
#endif
#ifndef FAN_ALL_INIT_FLAGS
# define FAN_ALL_INIT_FLAGS      (FAN_CLOEXEC | FAN_NONBLOCK | FAN_ALL_CLASS_BITS | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS)
#endif

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Initialize an fanotify instance
// This is expected to fail, as it requires CAPS_SYS_ADMIN.
//
// int fanotify_init(unsigned int flags, unsigned int event_f_flags)
SYSFUZZ(fanotify_init, __NR_fanotify_init, SYS_FAIL, CLONE_DEFAULT, 0)
{
    glong    retcode;
    glong    fd;

    retcode = spawn_syscall_lwp(this, &fd, __NR_fanotify_init,                                   // int
                                      typelib_get_integer_mask(FAN_ALL_INIT_FLAGS),              // unsigned int flags
                                      typelib_get_integer_mask(0xffffffff));                     // unsigned int event_f_flags

    if (retcode == ESUCCESS) {
        typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
    }

    return retcode;
}
