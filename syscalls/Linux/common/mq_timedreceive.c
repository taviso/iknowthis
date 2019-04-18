#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Receive a message from a message queue.
// ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio, const struct timespec *abs_timeout);
SYSFUZZ(mq_timedreceive, __NR_mq_timedreceive, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    msg_ptr;
    gpointer    msg_prio;
    gpointer    abs_timeout;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_mq_timedreceive,                           // ssize_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // mqd_t mqdes
                                typelib_get_buffer(&msg_ptr, PAGE_SIZE),                    // char *msg_ptr
                                typelib_get_integer(),                                      // size_t msg_len
                                typelib_get_buffer(&msg_prio, PAGE_SIZE),                   // unsigned *msg_prio
                                typelib_get_buffer(&abs_timeout, PAGE_SIZE));               // const struct timespec *abs_timeout

    typelib_clear_buffer(msg_ptr);
    typelib_clear_buffer(msg_prio);
    typelib_clear_buffer(abs_timeout);

    return retcode;
}

