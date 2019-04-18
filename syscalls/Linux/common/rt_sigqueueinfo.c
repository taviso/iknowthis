#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Send signal information to a signal. (wut?)
// long sys_rt_sigqueueinfo (int pid, int sig, siginfo_t *uinfo);
SYSFUZZ(rt_sigqueueinfo , __NR_rt_sigqueueinfo, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    uinfo;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigqueueinfo,                           // int
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),        // int pid
                                typelib_get_integer_range(0, NSIG),                         // int signum
                                typelib_get_buffer(&uinfo, PAGE_SIZE));                     // siginfo_t *uinfo

    typelib_clear_buffer(uinfo);
    return retcode;
}

