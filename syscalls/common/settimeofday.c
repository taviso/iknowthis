#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Get / set time
// int settimeofday(const struct timeval *tp, const struct timezone *tzp);
SYSFUZZ(settimeofday, SYS_settimeofday, SYS_FAIL, CLONE_DEFAULT, 0)
{
    gpointer    tv;
    gpointer    tz;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, SYS_settimeofday,                           // int
                                typelib_get_buffer(&tv, sizeof(struct timeval)),        // struct timeval *tv
                                typelib_get_buffer(&tz, sizeof(struct timezone)));      // struct timezone *tz

    typelib_clear_buffer(tv);
    typelib_clear_buffer(tz);
    return retcode;
}

