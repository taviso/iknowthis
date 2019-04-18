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

// Remove a message queue.
// mqd_t mq_unlink(const char *name);
SYSFUZZ(mq_unlink, __NR_mq_unlink, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar      *name;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_mq_unlink,                 // mqd_t
                                typelib_get_pathname(&name));               // const char *name

    g_free(name);

    return retcode;
}

