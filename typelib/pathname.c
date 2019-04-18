#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#ifndef __FreeBSD__
# ifndef _XOPEN_SOURCE
#  define _XOPEN_SOURCE 500
# endif
#endif

#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ftw.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__)
// FreeBSD has a slightly less configurable ftw implementation than Linux, but
// it's mostly compatible if we make the extra flags no-ops.
# define FTW_CONTINUE       0
# define FTW_SKIP_SUBTREE   0
# define FTW_SKIP_SIBLINGS  0
# define FTW_STOP           1
# define FTW_ACTIONRETVAL   0
#endif

// Many system calls expect a pathname as a parameter, and many pathnames
// expose new and interesting complexity that we should test. Device nodes,
// special files, and regular files on interesting filesystems, for example.
//
// We query what filesystems are mounted, and then try to traverse each
// filesystem looking for random candidates for testing.

// An array of mountpoints that we are aware of.
static GPtrArray * fs_mount_points;

// This constructor queries /prc/mounts and populates fs_mount_points array
// above.
static void __constructor typelib_find_mount_points(void)
{
    gchar   *mounts;
    gchar  **split;
    gchar   *mountpoint;
    gchar   *filesystem;
    gsize    length;
    gint     i;

    // Create a cleanup routine.
    void __destructor fini(void)
    {
        g_ptr_array_free(fs_mount_points, true);
    }

#if defined(__linux__)
    // Read the mounted filesystems.
    if (g_file_get_contents("/proc/mounts", &mounts, &length, NULL) == false) {
        g_error("unable to read mounted filesystems");
        g_abort();
    }
#elif defined(__FreeBSD__)
    // FreeBSD has not mtab, use mount.
    if (g_spawn_command_line_sync("mount -p", &mounts, NULL, NULL, NULL) == false) {
        g_error("unable to read mounted filesystems");
        g_abort();
    } else {
        length = strlen(mounts);
    }
#elif defined(__OpenBSD__)
    // FIXME I don't know how to do this on openbsd, read mount.c source.
    mounts = g_strdup("/dev/wd0a / ffs");
    length = strlen(mounts);
#else
# error need to determine what filesystems are mounted at runtime.
#endif


    split           = g_strsplit(mounts, "\n", -1);
    fs_mount_points = g_ptr_array_new();
    mountpoint      = g_malloc(length);
    filesystem      = g_malloc(length);

    for (i = 0; i < g_strv_length(split); i++) {
        if (sscanf(split[i], "%*s %s %s %*s %*u %*u", mountpoint, filesystem) >= 1) {
            // g_message("found %s on %s", filesystem, mountpoint);

            // Duplicate this string and add to array.
            g_ptr_array_add(fs_mount_points, g_strdup(mountpoint));
        }
    }

    // Finished.
    g_free(mounts);
    g_free(mountpoint);
    g_free(filesystem);
    g_strfreev(split);

    // There must be at least one filesystem.
    g_assert_cmpuint(fs_mount_points->len, >, 0);

    // g_debug("discovered %u mountpoints", fs_mount_points->len);

    return;
}

// This routine will choose a random pathname to use. Caller is required to
// g_free() the string produced when no longer needed. We accept an optional **
// parameter to store the result, as well as returning it, this is so that the
// call can be embedded in parameters, e.g.
// 
// syscall(__NR_open, typelib_get_pathname(&savedptr),
//                    typelib_get_integer(),
//                    typelib_get_integer());
// 
// g_free(savedptr);
//
gchar * typelib_get_pathname(gchar **pathname)
{
    const gchar *root;

    // Prepare a callback for nftw to use.
    int file_tree_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
    {
        // If we're at a reasonable depth, it's okay to break out
        // of directories. These numbers were selected because they seem to
        // work well, it's okay to change them.
        if (ftwbuf->level > 2) {
            switch (g_random_int_range(0, 512)) {
                case   0 ... 31: return FTW_SKIP_SUBTREE;
                case  32 ... 64: return FTW_SKIP_SIBLINGS;
            }
        }

        // Continue most of the time.
        if (g_random_int_range(0, 16))
            return FTW_CONTINUE;

        // Okay, this will do.

        // Older versions of nftw set fpath differently, differentiate by
        // checking for absolute vs relative pathname.
        if (g_str_has_prefix(fpath, G_DIR_SEPARATOR_S)) {
            *pathname = g_strdup(fpath);
        } else {
            // Old version, prepend the root string.
            *pathname = g_strjoin(NULL, root, G_DIR_SEPARATOR_S, fpath, NULL);
        }

        // Signal nftw that we want to stop.
        return FTW_STOP;
    }

    // Check if caller wants the pointer set.
    if (pathname == NULL) {
        pathname = g_alloca(sizeof(gpointer));
    }

    // Select a random mountpoint.
    root = g_ptr_array_index(fs_mount_points, g_random_int_range(0, fs_mount_points->len));

    // Begin Filesystem Walk.
    if (nftw(root, file_tree_callback, 32, FTW_DEPTH | FTW_ACTIONRETVAL | FTW_MOUNT | FTW_PHYS) != FTW_STOP) {
        gchar junk[PATH_MAX * 2] = {0};

        // Reached the end of the tree. Okay, make something up.
        *pathname = g_strdup_printf("%s%s%s", root,
                                              G_DIR_SEPARATOR_S,
                                              (gchar *) typelib_random_buffer(junk, sizeof junk - 1));
    }

    // Complete.
    return *pathname;
}
