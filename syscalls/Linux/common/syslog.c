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

// Read and/or clear kernel message ring buffer; set console_loglevel.
// int syslog(int type, char *bufp, int len);
SYSFUZZ(syslog, __NR_syslog, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong       retcode;
    gpointer    bufp;

    retcode = spawn_syscall_lwp(this, NULL, __NR_syslog,                                     // int
                                typelib_get_integer_range(0, 10),                            // int type
                                typelib_get_buffer(&bufp, PAGE_SIZE),                        // char *bufp
                                typelib_get_integer_range(0, PAGE_SIZE));                    // int len

    typelib_clear_buffer(bufp);

    return retcode;
}

