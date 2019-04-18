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

// Execution time profile.
SYSFUZZ(profil, __NR_profil, SYS_NONE, CLONE_DEFAULT, 0)
{
	gpointer    buf;
	gint        retcode;

	retcode = spawn_syscall_lwp(this, NULL, __NR_profil,                                    // int
	                            typelib_get_buffer(&buf, PAGE_SIZE),                        // unsigned short *buf
	                            PAGE_SIZE,                                                  // size_t bufsiz
	                            typelib_get_integer(),                                      // size_t offset
	                            typelib_get_integer());                                     // unsigned int scale


    typelib_clear_buffer(buf);

    return retcode;
}

