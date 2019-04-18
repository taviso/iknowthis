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

// Get real, effective and saved user/group IDs.
// int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
SYSFUZZ(getresgid32, __NR_getresgid32, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    rgid;
	gpointer    egid;
	gpointer    sgid;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_getresgid32,                                       // int
	                            typelib_get_buffer(&rgid, g_random_int_range(0, 8)),                // uid_t *rgid
	                            typelib_get_buffer(&egid, g_random_int_range(0, 8)),                // uid_t *egid
	                            typelib_get_buffer(&sgid, g_random_int_range(0, 8)));               // uid_t *sgid

    typelib_clear_buffer(rgid);
    typelib_clear_buffer(egid);
    typelib_clear_buffer(sgid);

    return retcode;
}

