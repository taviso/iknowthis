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

// Register for notification when a message is available
// mqd_t mq_notify(mqd_t mqdes, const struct sigevent *notification);
SYSFUZZ(mq_notify, __NR_mq_notify, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    notification;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_mq_notify,                                // mqd_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),       // mqd_t mqdes
                                typelib_get_buffer(&notification, PAGE_SIZE));             // const struct sigevent *notification

    typelib_clear_buffer(notification);

    return retcode;
}

