#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <linux/futex.h>
#include <errno.h>
#include <unistd.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get/set the list of robust futexes.
// long set_robust_list(struct robust_list_head *head, size_t len);
SYSFUZZ(set_robust_list, __NR_set_robust_list, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer     head;
    glong        retcode;

    // This routine rejects any call where sizeof(*head) != len.
    retcode = spawn_syscall_lwp(this, NULL, __NR_set_robust_list,                                       // long
                                typelib_get_buffer(&head, g_random_int_range(0, PAGE_SIZE)),            // struct robust_list_head *head
                                typelib_get_integer_selection(1, sizeof(struct robust_list_head)));     // size_t len

    typelib_clear_buffer(head);

    return retcode;
}

