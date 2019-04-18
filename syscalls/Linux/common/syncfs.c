#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef __NR_syncfs
# if defined(__i386__)
#  define __NR_syncfs 344
# elif defined(__x86_64__)
#  define __NR_syncfs 306
# else
#  error please define __NR_syncfs for your architecture
# endif
#endif

// Synchronize a single super.
// int syncfs(int fd);
SYSFUZZ(syncfs, __NR_syncfs, SYS_NONE, CLONE_DEFAULT, 0)
{
    return syscall_fast(__NR_syncfs, typelib_get_resource(this, NULL, RES_FILE, RF_NONE));
}

