#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/reboot.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set the list of robust futexes.
// long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
SYSFUZZ(get_robust_list, __NR_get_robust_list, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    head;
    gpointer    len;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_get_robust_list,                               // long
                                typelib_get_resource(this, NULL, RES_FORK, RF_NONE),            // pid_t pid
                                typelib_get_buffer(&head, PAGE_SIZE),                           // struct robust_list_head **head_ptr
                                typelib_get_buffer(&len, PAGE_SIZE));                           // size_t *len_ptr

    typelib_clear_buffer(head);
    typelib_clear_buffer(len);

    return retcode;
}

