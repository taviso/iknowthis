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

#ifndef __NR_fanotify_mark
# if defined(__i386__)
#  define __NR_fanotify_mark 339
# elif defined(__x86_64__)
#  define __NR_fanotify_mark 301
# else
#  error please define __NR_fanotify_mark for your architecture
# endif
#endif

#ifndef FAN_ALL_MARK_FLAGS
# define FAN_ACCESS                     0x00000001
# define FAN_MODIFY                     0x00000002
# define FAN_CLOSE_WRITE                0x00000008
# define FAN_CLOSE_NOWRITE              0x00000010
# define FAN_OPEN                       0x00000020
# define FAN_CLOSE                      (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE)
# define FAN_ALL_EVENTS                 (FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_OPEN)
# define FAN_MARK_ADD                   0x00000001
# define FAN_MARK_REMOVE                0x00000002
# define FAN_MARK_DONT_FOLLOW           0x00000004
# define FAN_MARK_ONLYDIR               0x00000008
# define FAN_MARK_MOUNT                 0x00000010
# define FAN_MARK_IGNORED_MASK          0x00000020
# define FAN_MARK_IGNORED_SURV_MODIFY   0x00000040
# define FAN_MARK_FLUSH                 0x00000080
# define FAN_MARK_ONDIR                 0x00000100
# define FAN_ALL_MARK_FLAGS             (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH)
# define FAN_OPEN_PERM                  0x00010000
# define FAN_ACCESS_PERM                0x00020000
# define FAN_ALL_PERM_EVENTS            (FAN_OPEN_PERM | FAN_ACCESS_PERM)
# define FAN_EVENT_ON_CHILD             0x08000000
#endif

// int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dfd, const char * pathname);
SYSFUZZ(fanotify_mark, __NR_fanotify_mark, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong    retcode;
    glong    fd;
    gchar   *pathname;


    retcode = spawn_syscall_lwp(this, &fd, __NR_fanotify_mark,                                                              // int
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                                  // int fanotify_fd,
                                      typelib_get_integer_selection(3, FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_FLUSH),      // unsigned int flags
#if __WORDSIZE == 32
                                      typelib_get_integer_selection(1, 0),                                                  // uint32_t mask_hi
                                      typelib_get_integer_mask(FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_EVENT_ON_CHILD),  // uint32_t mask_lo
#elif __WORDSIZE == 64
                                      typelib_get_integer_mask(FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_EVENT_ON_CHILD),
#endif
                                      typelib_get_resource(this, NULL, RES_FILE, RF_NONE),                                  // int dfd
                                      typelib_get_pathname(&pathname));                                                     // const char *pathname


    g_free(pathname);

    return retcode;
}
