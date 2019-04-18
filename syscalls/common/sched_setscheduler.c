#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Set and get scheduling policy/parameters
// int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
SYSFUZZ(sched_setscheduler, SYS_sched_setscheduler, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    param;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_sched_setscheduler,                                                             // int
                                typelib_get_integer_selection(2, 0, typelib_get_resource(this, NULL, RES_FORK, RF_NONE)),       // pid_t pid
                                typelib_get_integer(),                                                                          // int policy
                                typelib_get_buffer(&param, sizeof(struct sched_param)));                                        // struct sched_param *param

    typelib_clear_buffer(param);

    return retcode;
}

