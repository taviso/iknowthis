#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

SYSFUZZ(setdomainname, __NR_setdomainname, SYS_FAIL, CLONE_DEFAULT, 0)
{
	gpointer    name;
	glong       retcode;

	retcode = syscall_fast(__NR_setdomainname,                                                  // int
	                       typelib_get_buffer(&name, g_random_int_range(0, 0x1000)),            // const char *name
	                       typelib_get_integer());                                              // size_t len

    typelib_clear_buffer(name);
    return retcode;
}


