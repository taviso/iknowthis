#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get a Thread Local Storage (TLS) area
// int get_thread_area(struct user_desc *u_info);
SYSFUZZ(get_thread_area, __NR_get_thread_area, SYS_NONE, CLONE_FORK, 0)
{
    gpointer    u_info;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_get_thread_area,                               // int
                                typelib_get_buffer(&u_info, PAGE_SIZE));                        // struct user_desc *u_info

    typelib_clear_buffer(u_info);
    return retcode;
}

