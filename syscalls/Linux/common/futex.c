#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/futex.h>
#include <errno.h>
#include <unistd.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef FUTEX_WAIT_BITSET
# define FUTEX_WAIT_BITSET 0
#endif
#ifndef FUTEX_WAKE_BITSET
# define FUTEX_WAKE_BITSET 0
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
# define FUTEX_WAIT_REQUEUE_PI 0
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
# define FUTEX_CMP_REQUEUE_PI 0
#endif

// Fast Userspace Locking system call
// int futex(int *uaddr, int op, int val, const struct timespec *timeout,
//           int *uaddr2, int val3);
SYSFUZZ(futex, __NR_futex, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    uaddr;
    gpointer    timeout;
    gpointer    uaddr2;
    glong       retcode;
    gint        cmd;

    cmd     = typelib_get_integer_selection(12, FUTEX_WAIT,
                                                FUTEX_WAIT_BITSET,
                                                FUTEX_WAKE,
                                                FUTEX_WAKE_BITSET,
                                                FUTEX_REQUEUE,
                                                FUTEX_CMP_REQUEUE,
                                                FUTEX_WAKE_OP,
                                                FUTEX_LOCK_PI,
                                                FUTEX_UNLOCK_PI,
                                                FUTEX_TRYLOCK_PI,
                                                FUTEX_WAIT_REQUEUE_PI,
                                                FUTEX_CMP_REQUEUE_PI);

    if (g_random_boolean()) {
        cmd |= FUTEX_PRIVATE_FLAG;
    }

    retcode = spawn_syscall_lwp(this, NULL, __NR_futex,                                     // int
                                typelib_get_buffer(&uaddr, g_random_int_range(0, 32)),      // int *uaddr
                                cmd,                                                        // int op
                                typelib_get_integer(),                                      // int val
                                typelib_get_buffer(&timeout, PAGE_SIZE),                    // const struct timespec *timeout
                                typelib_get_buffer(&uaddr2, g_random_int_range(0, 32)),     // int *uaddr2
                                typelib_get_integer());                                     // int val3

    typelib_clear_buffer(uaddr);
    typelib_clear_buffer(uaddr2);
    typelib_clear_buffer(timeout);

    return retcode;
}

