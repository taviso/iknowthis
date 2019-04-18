#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// control process profiling
// int profil(char *samples, size_t size, vm_offset_t offset, int scale);
SYSFUZZ(profil, SYS_profil, SYS_NONE, CLONE_DEFAULT, 0)
{
    glong    retcode;
    gpointer samples;

    retcode = spawn_syscall_lwp(this, NULL, SYS_profil,                     // int
                                typelib_get_buffer(&samples, PAGE_SIZE),    // char *samples
                                typelib_get_integer(),                      // size_t size
                                typelib_get_integer(),                      // vm_offset_t offset,
                                typelib_get_integer());                     // int scale

    typelib_clear_buffer(samples);
    return retcode;
}
