#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Execute program.
// int execve(const char *filename, char *const argv[], char *const envp[]);
SYSFUZZ(execve, SYS_execve, SYS_NONE, CLONE_DEFAULT, 1000)
{
    glong       retcode;
    gchar      *pathname;
    guint       acnt    = g_random_int_range(1, 32);
    guint       ecnt    = g_random_int_range(1, 32);
    gpointer   *argv    = g_malloc(acnt * sizeof(gpointer));
    gpointer   *envp    = g_malloc(ecnt * sizeof(gpointer));

    for (guint i = 0; i < acnt - 1; i++) {
        typelib_get_buffer(&argv[i], g_random_int_range(0, PAGE_SIZE));
    }

    for (guint i = 0; i < ecnt - 1; i++) {
        typelib_get_buffer(&envp[i], g_random_int_range(0, PAGE_SIZE));
    }

    argv[acnt - 1] = envp[ecnt - 1] = NULL;

    // Execute system call.
    if (g_random_boolean()) {
        retcode = spawn_syscall_lwp(this, NULL, SYS_execve, typelib_get_pathname(&pathname), argv, envp);
    } else {
        retcode = spawn_syscall_lwp(this, NULL, SYS_execve, typelib_get_pathname(&pathname), *argv, *envp);
    }

    // Clean up
    g_free(pathname);

    for (guint i = 0; i < acnt - 1; i++) {
        typelib_clear_buffer(argv[i]);
    }

    for (guint i = 0; i < ecnt - 1; i++) {
        typelib_clear_buffer(envp[i]);
    }

    g_free(argv);
    g_free(envp);

    return retcode;
}
