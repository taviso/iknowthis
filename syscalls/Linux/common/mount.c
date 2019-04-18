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

// Mount file system.
// int mount(const char *source, const char *target,
//           const char *filesystemtype, unsigned long mountflags,
//           const void *data);
SYSFUZZ(mount, __NR_mount, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gchar   *source;
    gchar   *target;
    gpointer filesystemtype;
    gpointer data;
    glong    retcode;

    // XXX: parse /proc/filesystems in typelib, typelib_fs_get?
    retcode = spawn_syscall_lwp(this, NULL, __NR_mount,                                      // int
                         typelib_get_pathname(&source),                                      // const char *source
                         typelib_get_pathname(&target),                                      // const char *target
                         typelib_get_buffer(&filesystemtype, g_random_int_range(0, 0x1000)), // const char *filesystemtype
                         typelib_get_integer(),                                              // unsigned long mountflags
                         typelib_get_buffer(&data, g_random_int_range(0, 0x1000)));          // const void *data

    g_assert_cmpint(retcode, !=, ESUCCESS);

    typelib_clear_buffer(filesystemtype);
    typelib_clear_buffer(data);
    g_free(source);
    g_free(target);

    return retcode;
}
