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

// Loads a new kernel image to memory.
// long kexec_load(unsigned long entry, unsigned long nr_segments,
//                 struct kexec_segment *segments, unsigned long flags);
SYSFUZZ(kexec_load, __NR_kexec_load, SYS_FAIL | SYS_BORING | SYS_SAFE, CLONE_DEFAULT, 0)
{
    gpointer    segments;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_kexec_load,                                // long
                                typelib_get_integer(),                                      // unsigned long entry
                                typelib_get_integer(),                                      // unsigned long nr_segments
                                typelib_get_buffer(&segments, PAGE_SIZE),                   // struct kexec_segment *segments
                                typelib_get_integer());                                     // unsigned long flags

    typelib_clear_buffer(segments);

    return retcode;
}

