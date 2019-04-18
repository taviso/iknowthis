#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef TFD_NONBLOCK
# define TFD_NONBLOCK O_NONBLOCK
#endif
#ifndef TFD_CLOEXEC
# define TFD_CLOEXEC O_CLOEXEC
#endif

// Timers that notify via file descriptors.
// int timerfd_settime(int fd, int flags,
//                     const struct itimerspec *new_value,
//                     struct itimerspec *old_value);
SYSFUZZ(timerfd_settime, __NR_timerfd_settime, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gpointer    new_value;
    gpointer    old_value;

    retcode = spawn_syscall_lwp(this, NULL, __NR_timerfd_settime,                                           // int
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                        // int fd
                                typelib_get_integer_selection(4, TFD_NONBLOCK,
                                                                 TFD_CLOEXEC,
                                                                 TFD_NONBLOCK | TFD_CLOEXEC,
                                                                 0),                                        // int flags
                                typelib_get_buffer(&new_value, PAGE_SIZE),                                  // const struct itimerspec *new_value
                                typelib_get_buffer(&old_value, PAGE_SIZE));                                 // struct itimerspec *old_value

    typelib_clear_buffer(new_value);
    typelib_clear_buffer(old_value);
    return retcode;
}
