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

// Synchronously  wait for queued signals specified in uthese.
// long sys_rt_sigtimedwait (const sigset_t *uthese, siginfo_t *uinfo,
//                           const struct struct timespec *uts,
//                           size_t sigsetsize);
// long long struct struct... :-)
SYSFUZZ(rt_sigtimedwait, __NR_rt_sigtimedwait, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gpointer    uthese;
    gpointer    uinfo;
    gpointer    uts;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_rt_sigtimedwait,                       // int
                                typelib_get_buffer(&uthese, sizeof(sigset_t)),          // sigset_t *uthese
                                typelib_get_buffer(&uinfo, sizeof(sigset_t)),           // sigset_t *uinfo
                                typelib_get_buffer(&uts, sizeof(struct timespec)),      // const struct struct timespec *uts
                                typelib_get_integer_selection(1, sizeof(guint64)));     // size_t sigsetsize

    typelib_clear_buffer(uthese);
    typelib_clear_buffer(uinfo);
    typelib_clear_buffer(uts);
    return retcode;
}

