#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef KEY_SPEC_THREAD_KEYRING
# define KEY_SPEC_THREAD_KEYRING         -1
#endif
#ifndef KEY_SPEC_PROCESS_KEYRING
# define KEY_SPEC_PROCESS_KEYRING        -2
# define KEY_SPEC_SESSION_KEYRING        -3
# define KEY_SPEC_USER_KEYRING           -4
# define KEY_SPEC_USER_SESSION_KEYRING   -5
# define KEY_SPEC_GROUP_KEYRING          -6
# define KEY_SPEC_REQKEY_AUTH_KEY        -7
#endif

// Add a key to the kernel’s key management facility.
// key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring);
SYSFUZZ(add_key, __NR_add_key, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer    desc;
    gpointer    payload;
    glong       retcode;
    gpointer    keytype;
    glong       serial;

    // TODO: use resource management for key serials

    retcode = spawn_syscall_lwp(this, &serial, __NR_add_key,                                     // key_serial_t
                                typelib_get_buffer(&keytype, PAGE_SIZE),                         // const char *type
                                typelib_get_buffer(&desc, PAGE_SIZE),                            // const char *desc
                                typelib_get_buffer(&payload, PAGE_SIZE),                         // const void *payload
                                typelib_get_integer_range(0, PAGE_SIZE),                         // size_t plen
                                typelib_get_integer_selection(5, KEY_SPEC_THREAD_KEYRING,        // key_serial_t keyring
                                                                 KEY_SPEC_PROCESS_KEYRING,
                                                                 KEY_SPEC_SESSION_KEYRING,
                                                                 KEY_SPEC_USER_KEYRING,
                                                                 KEY_SPEC_USER_SESSION_KEYRING));

    typelib_clear_buffer(keytype);
    typelib_clear_buffer(desc);
    typelib_clear_buffer(payload);
    return retcode;
}

