#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Mount file system.
// int mount(const char *type, const char *dir, int flags, void *data);
SYSFUZZ(mount, SYS_mount, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gchar   *source;
    gpointer filesystemtype;
    gpointer data;
    glong    retcode;

    // XXX: parse /proc/filesystems in typelib, typelib_fs_get?
    retcode = spawn_syscall_lwp(this, NULL, SYS_mount,                                       // int
                         typelib_get_buffer(&filesystemtype, PAGE_SIZE),                     // const char *filesystemtype
                         typelib_get_pathname(&source),                                      // const char *source
                         typelib_get_integer(),                                              // unsigned long mountflags
                         typelib_get_buffer(&data, PAGE_SIZE));                              // const void *data

    g_assert_cmpint(retcode, !=, ESUCCESS);

    typelib_clear_buffer(filesystemtype);
    typelib_clear_buffer(data);
    g_free(source);
    return retcode;
}
