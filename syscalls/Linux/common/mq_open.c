#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Open a message queue
// mqd_t mq_open(const char *name, int oflag, mode_t mode,
//               struct mq_attr *attr);
SYSFUZZ(mq_open, __NR_mq_open, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gchar      *name;
    gpointer    attr;
    glong       retcode;
    glong       mqd;

    retcode = spawn_syscall_lwp(this, &mqd, __NR_mq_open,                                   // mqd_t
                                typelib_get_pathname(&name),                                // const char *name
                                typelib_get_integer(),                                      // int oflag
                                typelib_get_integer(),                                      // mode_t mode
                                typelib_get_buffer(&attr, PAGE_SIZE));                      // struct mq_attr *attr

    typelib_clear_buffer(attr);

    g_free(name);

    if (retcode == ESUCCESS) {
        typelib_add_resource(this, mqd, RES_FILE, RF_NONE, destroy_open_file);
    }

    return retcode;
}
