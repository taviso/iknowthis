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

// Set/get capabilities of thread(s).
// int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
SYSFUZZ(capset, __NR_capset, SYS_FAIL | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gpointer    hdrp;
    gpointer    datap;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_capset,                                // int
                                typelib_get_buffer(&hdrp, PAGE_SIZE),                   // const cap_user_header_t hdrp
                                typelib_get_buffer(&datap, PAGE_SIZE));                 // const cap_user_data_t datap

    typelib_clear_buffer(hdrp);
    typelib_clear_buffer(datap);

    return retcode;
}

