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

// Get file system type information.
// int sysfs(int option, const char *fsname);
// int sysfs(int option, unsigned int fs_index, char *buf);
// int sysfs(int option);
SYSFUZZ(sysfs, __NR_sysfs, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    fsname;
	gpointer    buf;
	glong       retcode;

    switch (g_random_int_range(0, 4)) {
    	case    1: retcode = spawn_syscall_lwp(this, NULL, __NR_sysfs,                      // int
    	                                       1,                                           // int option
    	                                       typelib_get_buffer(&fsname, g_random_int_range(0, 0x1000)));  // const char *fsname
                   typelib_clear_buffer(fsname);
                   return retcode;
        case    2: retcode = spawn_syscall_lwp(this, NULL, __NR_sysfs,                      // int
                                               2,                                           // int option
                                               typelib_get_integer(),                       // unsigned int fs_index
                                               typelib_get_buffer(&buf, g_random_int_range(0, 0x1000)));  // char *buf
                   typelib_clear_buffer(buf);
                   return retcode;
        case    3: return spawn_syscall_lwp(this, NULL, __NR_sysfs,                         // int
                                            3);                                             // int option
        // XXX FIXME
        default:   return spawn_syscall_lwp(this, NULL, __NR_sysfs,                         // int
                                            typelib_get_integer(),                          // int option
                                            NULL,
                                            NULL);                                        
    }

    g_assert_not_reached();
}

