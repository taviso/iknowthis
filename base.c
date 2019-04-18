#include <glib.h>
#include <sys/uio.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"

// typelib routines for primitive types.
gulong typelib_get_integer(void)
{
    gulong result = 0;

    switch (g_random_int_range(0, 3)) {
        case 0: result   = g_random_int() & g_random_int();     // Low density
#if __WORDSIZE == 64
                result <<= 32;
                result  |= g_random_int() & g_random_int();
#endif
                break;
        case 1: result   = g_random_int() | g_random_int();     // High density
#if __WORDSIZE == 64
                result <<= 32;
                result  |= g_random_int() | g_random_int();
#endif
                break;
        case 2: result   = g_random_int();                      // Even density
#if __WORDSIZE == 64
                result <<= 32;
                result  |= g_random_int();
#endif
                break;
        default: g_assert_not_reached();
    }
    return result;
}

// Note that it might return out of range occasionally.
gulong typelib_get_integer_range(guint32 start, guint32 end)
{
    g_assert_cmpuint(start, <, end);

    if (g_random_int_range(0, 1024)) {
        return g_random_int_range(start, end + 1);
    }

    return typelib_get_integer();
}

gulong typelib_get_integer_selection(guint count, ...)
{
    va_list     ap;
    guint       i;
    guint       current;
    guint       selected;

    // Verify I'm not called with insane parameters.
    g_assert_cmpuint(count, >, 0);

    // Possibly break the rules.
    if (g_random_int_range(0, 1024) == 0) {
        return typelib_get_integer();
    }

    // Choose a random argument.
    selected = g_random_int_range(0, count);
    i        = 0;

    va_start(ap, count); {
        do {
           current = va_arg(ap, gulong);
        } while (i++ < selected);
    } va_end(ap);

    return current;
}

gulong typelib_get_integer_mask(gulong mask)
{
    return typelib_get_integer() & mask;
}

gpointer typelib_get_iovec(gpointer *iov, gint *count, guint flags)
{
    guint         i;
    struct iovec *vec;

    *count  = g_random_int_range(0, 8);
    vec     = typelib_get_buffer(iov, *count * sizeof(struct iovec));

    for (i = 0; i < *count; i++) {
        vec[i].iov_len    = g_random_int_range(0, PAGE_SIZE);
        vec[i].iov_base   = typelib_get_buffer(NULL, vec[i].iov_len);
    }

    return vec;
}

void typelib_clear_iovec(gpointer iovec, gint count, guint flags)
{
    guint         i;
    struct iovec *p = iovec;

    for (i = 0; i < count; i++) {
        typelib_clear_buffer(p[i].iov_base);
    }

    typelib_clear_buffer(p);

    return;
}
