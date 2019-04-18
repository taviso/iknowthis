#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Process trace.
// long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
SYSFUZZ(ptrace, __NR_ptrace, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gint        request;
    guintptr    addr;
    guintptr    data;
    gboolean    pointer;

    pointer = false;
    addr    = typelib_get_integer();
    data    = typelib_get_integer();
    request = typelib_get_integer_mask(0xFF);

    // Maybe OR in the extended options.
    if (g_random_int_range(0, 3) == 0) {
        request |= 0x4200;
    }

    switch (request) {
        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA:
        case PTRACE_SETREGS:
        case PTRACE_SETFPREGS:
                // FIXME: I don't currently support these.
                return ENOSYS;
        case PTRACE_GETREGS:
        case PTRACE_GETFPREGS:
        case PTRACE_GETSIGINFO:
        case PTRACE_SETSIGINFO:
        case PTRACE_GETEVENTMSG:
                 pointer = true;
                 data    = GPOINTER_TO_UINT(typelib_get_buffer(NULL, PAGE_SIZE));
                 break;
        case PTRACE_SETOPTIONS:
#ifdef PTRACE_O_MASK
                 data    = typelib_get_integer_mask(PTRACE_O_MASK);
#endif
                 break;
        case PTRACE_SYSCALL:
        case PTRACE_SINGLESTEP:
        case PTRACE_CONT:
#ifdef PTRACE_SYSEMU
        case PTRACE_SYSEMU:
#endif
#ifdef PTRACE_SYSEMU_SINGLESTEP
        case PTRACE_SYSEMU_SINGLESTEP:
#endif
        case PTRACE_KILL:
        case PTRACE_DETACH:
                // Probably can do this..
                // data    = typelib_get_integer_range(0, NSIG);
                //
                // But I don't want to kill it too often..
                data    = typelib_get_integer_selection(1, 0);
                break;
    }


    retcode = spawn_syscall_lwp(this, NULL, __NR_ptrace,                                // long
                                request,                                                // long request
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),    // pid_t pid
                                addr,                                                   // void *addr
                                data);                                                  // void *data

    if (pointer) {
        typelib_clear_buffer(GUINT_TO_POINTER(data));
    }

    return retcode;
}
