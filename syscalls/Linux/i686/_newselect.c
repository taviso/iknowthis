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


// Synchronous I/O multiplexing.
// XXX FIXME
SYSFUZZ(_newselect, __NR__newselect, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    return 0;
}

