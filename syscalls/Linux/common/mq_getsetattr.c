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

// Get/set message queue attributes.
// mqd_t mq_getsetattr(mqd_t mqdes, struct mq_attr *newattr, struct mq_attr *oldattr);
SYSFUZZ(mq_getsetattr, __NR_mq_getsetattr, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    newattr;
    gpointer    oldattr;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_mq_getsetattr,                             // mqd_t
                                typelib_get_resource(this, NULL, RES_FILE, RF_NONE),        // mqd_t mqdes
                                typelib_get_buffer(&newattr, PAGE_SIZE),                    // struct mq_attr *newattr
                                typelib_get_buffer(&oldattr, PAGE_SIZE));                   // struct mq_attr *oldattr

    typelib_clear_buffer(newattr);
    typelib_clear_buffer(oldattr);

    return retcode;
}
