#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

static gpointer fuzzerstack;
static gpointer watchdogstack;

// System call number and parameters, and where the return value should go.
struct context {
    glong   *status;
    glong    sysno;
    gulong   arg0;
    gulong   arg1;
    gulong   arg2;
    gulong   arg3;
    gulong   arg4;
    gulong   arg5;
    gulong   arg6;
};

#if defined(__FreeBSD__) || defined(__OpenBSD__)
# define MAP_GROWSDOWN 0
# define __WALL 0
#endif

// Allocate space for lwp stacks.
static void __constructor init_thread_stacks(void)
{
    fuzzerstack   = mmap(NULL,
                         PAGE_SIZE * 32,
                         PROT_READ | PROT_WRITE,
                         MAP_ANON  | MAP_PRIVATE | MAP_GROWSDOWN,
                         -1,
                         0);
    watchdogstack = mmap(NULL,
                         PAGE_SIZE * 32,
                         PROT_READ | PROT_WRITE,
                         MAP_ANON  | MAP_PRIVATE | MAP_GROWSDOWN,
                         -1,
                         0);

    g_assert(fuzzerstack != MAP_FAILED);
    g_assert(watchdogstack != MAP_FAILED);

    fuzzerstack     += PAGE_SIZE * 16;
    watchdogstack   += PAGE_SIZE * 16;

    return;
}

struct watchdog {
    syscall_fuzzer_t    *fuzzer;
    pid_t                pid;
};

// Thread used to monitor for fuzzer for timeout.
static gint watchdog_thread_func(gpointer parameters)
{
    struct watchdog *params  = parameters;
    struct timespec  request = {
        .tv_sec     = params->fuzzer->timeout ? 0 : 1,                    // Default timeout
        .tv_nsec    = params->fuzzer->timeout * 1000,                     // Microseconds.
    };

    // Convert timeout to nanoseconds, and use nanosleep to delay.
    nanosleep(&request, NULL);

    if (params->fuzzer->timeout == 0) {
        g_message("fuzzer %s reached the default cap on execution time", params->fuzzer->name);
    }

    // I'm still here, so kill the thread.
    if (kill(params->pid, SIGKILL) != 0) {
        // This is normal, just a small race condition.
        g_assert_cmpint(errno, ==, ESRCH);

        g_message("watchdog thread failed to terminate hung process %d, %s",
                  params->pid,
                  custom_strerror_wrapper(errno));
    }

    return 0;
}

// Execute a systemcall, extract the required parameters from the passed
// structure.
gint lwp_systemcall_routine(gpointer param)
{
    glong           retcode = 0;
    struct context *context = param;

    // Initialise, in case I'm killed.
    *(context->status) = -ESUCCESS;
    errno              =  ESUCCESS;

    // Execute system call.
    retcode = syscall(context->sysno,
                      context->arg0,
                      context->arg1,
                      context->arg2,
                      context->arg3,
                      context->arg4,
                      context->arg5,
                      context->arg6);

    // Find the status code.
    *(context->status) = retcode == -1 ? -errno : retcode;

    return 0;
}

gint spawn_syscall_lwp(syscall_fuzzer_t *this, glong *status, glong sysno, ...)
{
    gint            watchdogpid, childpid;
    gint            watchdogstatus, childstatus;
    gint            watchdogret;
    glong           retcode;
    va_list         ap;

    struct watchdog watchdog = {
        .fuzzer     = this,
    };
    struct context  context = {
        .status     = status ? status : &retcode,
        .sysno      = sysno,
    };

    va_start(ap, sysno);

    g_assert_cmpint(this->number, ==, sysno);

    // FIXME: just va_copy and parse the va_list around, but this doesnt work
    //        reliably on x64, find out why.
    context.arg0    = va_arg(ap, gulong);
    context.arg1    = va_arg(ap, gulong);
    context.arg2    = va_arg(ap, gulong);
    context.arg3    = va_arg(ap, gulong);
    context.arg4    = va_arg(ap, gulong);
    context.arg5    = va_arg(ap, gulong);
    context.arg6    = va_arg(ap, gulong);

    // If nothing can go wrong with this call, don't waste time
    // with clones.
    if (this->flags & SYS_SAFE) {
        if (lwp_systemcall_routine(&context) != 0) {
            g_warning("fuzzer %s was marked safe, but something weird happened", this->name);
        }

        // Calculate return code.
        return (gulong)(*(context.status)) > (gulong)(-4095)
                            ? -*(context.status)
                            : 0;
    }

#if defined(__linux__)
    // Spawn the fuzzer.
    if ((watchdog.pid = clone(lwp_systemcall_routine, fuzzerstack, this->shared, &context)) == -1) {
        g_critical("failed to spawn lwp for fuzzer %s, %s", this->name, custom_strerror_wrapper(errno));
    }

    // Spawn watchdog.
    if ((watchdogpid = clone(watchdog_thread_func, watchdogstack, CLONE_DEFAULT, &watchdog)) == -1) {
        g_critical("failed to spawn watchdog thread for %s, %s", this->name, custom_strerror_wrapper(errno));

        // Kill it to prevent hangs.
        kill(watchdog.pid, SIGKILL);
    }
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
    // Spawn the fuzzer.
    if ((watchdog.pid = rfork_thread(this->shared, fuzzerstack, lwp_systemcall_routine, &context)) == -1) {
        g_critical("failed to spawn lwp for fuzzer %s, %s", this->name, custom_strerror_wrapper(errno));
    }

    // Spawn watchdog.
    if ((watchdogpid = rfork_thread(CLONE_DEFAULT, watchdogstack, watchdog_thread_func, &watchdog)) == -1) {
        g_critical("failed to spawn watchdog thread for %s, %s", this->name, custom_strerror_wrapper(errno));

        // Kill it to prevent hangs.
        kill(watchdog.pid, SIGKILL);
    }
#else
# error need to know how to isolate threads on your architecture.
#endif

    // And now we play the waiting game.
    childpid = waitpid(watchdog.pid, &childstatus, __WALL);

    // Child has returned, (possibly) kill watchdog. Note that it might already
    // be dead, if the child timedout.
    kill(watchdogpid, SIGKILL);

    // Wait for the watchdog to return.
    watchdogret = waitpid(watchdogpid, &watchdogstatus, __WALL);

    // Check that worked.
    if (childpid == -1 || watchdogret == -1) {
        g_critical("failed to wait for one of my lwps for %s, %s", this->name, custom_strerror_wrapper(errno));
    }

    if (childpid != -1 ) {
        g_assert_cmpint(childpid, ==, watchdog.pid);
    }
    if (watchdogpid != -1) {
        g_assert_cmpint(watchdogret, ==, watchdogpid);
    }

    // Child completed before timeout.
    if (WIFEXITED(childstatus)) {
        return (gulong)(*(context.status)) > (gulong)(-4095)
                            ? -*(context.status)
                            : 0;
    }

    // Child crashed.
    if (WIFSIGNALED(childstatus) && WTERMSIG(childstatus) != SIGKILL)
        return EKILLED;

    // Watchdog killed just after killing fuzzer.
    if (WIFSIGNALED(childstatus) && WTERMSIG(childstatus) == SIGKILL)
        return ETIMEOUT;

    if (WIFEXITED(childstatus)) {
        g_debug("fuzzer %s child exited with %d", this->name, WEXITSTATUS(childstatus));
    }

    if (WIFSIGNALED(childstatus)) {
        g_debug("fuzzer %s child terminated with %d", this->name, WTERMSIG(childstatus));
    }

    if (WIFEXITED(watchdogstatus)) {
        g_debug("watchdog exited with %d", WEXITSTATUS(childstatus));
    }

    if (WIFSIGNALED(watchdogstatus)) {
        g_debug("watchdog terminated with %d", WTERMSIG(childstatus));
    }

    // Done with stack frame.
    va_end(ap);

    // FIXME: What else could happen?
    g_assert_not_reached();
}
