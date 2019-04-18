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

#ifndef __NR_name_to_handle_at
# if defined(__i386__)
#  define __NR_name_to_handle_at 341
# elif defined(__x86_64__)
#  define __NR_name_to_handle_at 303
# else
#  error please define __NR_name_to_handle_at for your architecture
# endif

// I guess these won't be defined either.
# define AT_EMPTY_PATH       0x1000  /* Allow empty relative pathname */
# define AT_SYMLINK_FOLLOW   0x400   /* Follow symbolic links.  */
#endif

// It looks like this:
// struct file_handle {
//     guint32       handle_bytes;
//     int           handle_type;
//     unsigned char f_handle[0];
// };

// Convert name to handle.
// int name_to_handle(int dfd, const char *name, struct file_handle *handle, int *mnt_id, int flag);
SYSFUZZ(name_to_handle_at, __NR_name_to_handle_at, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gchar       *pathname;
    gpointer     handle;
    gpointer     mntid;
    glong        retcode;

    // Execute systemcall.
    retcode = spawn_syscall_lwp(this, NULL, __NR_name_to_handle_at,                                 // int
                                     typelib_get_resource(this, NULL, RES_FILE, RF_NONE),           // int dirfd
                                     typelib_get_pathname(&pathname),                               // const char *name
                                     typelib_get_buffer(&handle, PAGE_SIZE),                        // struct file_handle *handle
                                     typelib_get_buffer(&mntid, PAGE_SIZE),                         // int *mnt_id
                                     typelib_get_integer_mask(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH));  // int flags

    // Release string.
    g_free(pathname);
    typelib_clear_buffer(mntid);
    typelib_clear_buffer(handle);

    return retcode;
}

