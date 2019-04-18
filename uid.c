#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <errno.h>
#include <glib.h>
#include <sched.h>
#include <search.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

static gint find_unused_uid(void)
{
    // Scan for an unused uid by waiting for getpwuid to return NULL. I don't
    // think this is the best strategy, I'll come up with a better one at
    // some point (maybe require a dedicated user?).
    for (gint uid = 0;; uid++) {
        if (getpwuid(uid) == NULL) {
            g_message("find_unused_uid() selected uid %d for fuzzing", uid);
            return uid;
        }
    }

    g_assert_not_reached();
}

