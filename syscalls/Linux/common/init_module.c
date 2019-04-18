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

// Initialize a loadable module entry.
SYSFUZZ(init_module, __NR_init_module, SYS_FAIL, CLONE_DEFAULT, 0)
{
	gpointer    name;
	gpointer    image;
	glong       retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_init_module,                               // int
	                            typelib_get_buffer(&name, g_random_int_range(0, 0x1000)),   // const char *name
	                            typelib_get_buffer(&image, g_random_int_range(0, 0x1000))); // struct module *image

    typelib_clear_buffer(name);
    typelib_clear_buffer(image);

    return retcode;
}

