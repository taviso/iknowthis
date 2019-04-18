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

// Request a key from the kernel’s key management facility
//       key_serial_t request_key(const char *type, const char *description,
//       const char *callout_info, key_serial_t keyring);
// XXX: i bet i need typelib support for those fucking serials.
SYSFUZZ(request_key, __NR_request_key, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    type;
    gpointer    desc;
    gpointer    callout;
    glong       retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_request_key,                                    // key_serial_t
                                typelib_get_buffer(&type, g_random_int_range(0, 1024)),          // const char *type
                                typelib_get_buffer(&desc, g_random_int_range(0, 1024)),          // const char *desc
                                typelib_get_buffer(&callout, g_random_int_range(0, PAGE_SIZE)),  // const void *callout
                                g_random_boolean()
                                    ? + typelib_get_integer()
                                    : - typelib_get_integer_range(0, 32));                       // key_serial_t keyring

    typelib_clear_buffer(type);
    typelib_clear_buffer(desc);
    typelib_clear_buffer(callout);
    return retcode;
}

