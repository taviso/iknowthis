#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"



// Operations on a process.
// int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
SYSFUZZ(prctl, __NR_prctl, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint        option;
    guintptr    arg2;
    guintptr    arg3;
    guintptr    arg4;
    guintptr    arg5;
    glong       retcode;
    gboolean    pointer;
    
    option  = typelib_get_integer_range(0, 128);
    pointer = false;
    arg2    = typelib_get_integer();
    arg3    = typelib_get_integer();
    arg4    = typelib_get_integer();
    arg5    = typelib_get_integer();

    switch (option) {
        case PR_SET_PDEATHSIG:
            arg2 = typelib_get_integer_range(0, NSIG);
            break;
        case PR_GET_PDEATHSIG:
            pointer = true;
            typelib_get_buffer((gpointer) &arg2, g_random_int_range(0, PAGE_SIZE));
            break;
        case PR_GET_DUMPABLE:
            arg2 = typelib_get_integer_range(0, 1);
            break;
        case PR_SET_TIMING:
            arg2 = typelib_get_integer_selection(1, PR_TIMING_STATISTICAL);
            break;
        case PR_SET_NAME:
        case PR_GET_NAME:
            pointer = true;
            typelib_get_buffer((gpointer)(&arg2), g_random_int_range(0, PAGE_SIZE));
            break;
#ifdef PR_MCE_KILL
        case PR_MCE_KILL:
            arg2 = typelib_get_integer_selection(2, PR_MCE_KILL_CLEAR, PR_MCE_KILL_SET);
            arg3 = typelib_get_integer_selection(3, PR_MCE_KILL_EARLY, PR_MCE_KILL_LATE, PR_MCE_KILL_DEFAULT);
            arg4 = typelib_get_integer_selection(1, 0);
            arg5 = typelib_get_integer_selection(1, 0);
            break;
        case PR_MCE_KILL_GET:
            arg2 = typelib_get_integer_selection(1, 0);
            arg3 = typelib_get_integer_selection(1, 0);
            arg4 = typelib_get_integer_selection(1, 0);
            arg5 = typelib_get_integer_selection(1, 0);
            break;
#endif
        default:
            if (g_random_boolean()) {
                arg2 = typelib_get_integer();
            } else {
                pointer = true;
                typelib_get_buffer((gpointer)(&arg2), g_random_int_range(0, PAGE_SIZE));
            }
    }

    retcode = spawn_syscall_lwp(this, NULL, __NR_prctl,                                                 // int
                                option,                                                                 // int option
                                arg2,                                                                   // unsigned long arg2
                                arg3,                                                                   // unsigned long arg3
                                arg4,                                                                   // unsigned long arg4
                                arg5);                                                                  // unsigned long arg5
    
    if (pointer) {
        typelib_clear_buffer((gpointer)(arg2));
    }
    
    return retcode;
}

