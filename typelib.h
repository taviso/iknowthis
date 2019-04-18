#ifndef __TYPELIB_H
#define __TYPELIB_H
#pragma once

#ifndef __constructor
# define __constructor __attribute__((constructor))
#endif
#ifndef __destructor
# define __destructor __attribute__((destructor))
#endif

#ifndef g_assert_cmpstr
# define g_assert_cmpstr(x, y, z) 
# define g_strcmp0 strcmp
# define O_CLOEXEC 04
#endif
#ifndef g_assert_cmpint
# define g_assert_cmpint(x, y, z)
#endif
#ifndef g_assert_cmpuint
# define g_assert_cmpuint(x, y, z)
#endif
#if !GLIB_CHECK_VERSION(2, 18, 0)
    // Debian Armel has a crazy old glib. 
    typedef signed long gintptr;
    typedef unsigned long guintptr;
    #define G_GINTPTR_FORMAT "li"
    #define G_GUINTPTR_FORMAT "lu"
    #define G_GINTPTR_MODIFIER "l"
    #define G_GUINTPTR_MODIFIED "lu"
    #undef g_assert_cmpstr
    #define g_assert_cmpstr(x, y, z)
#endif
#if !GLIB_CHECK_VERSION(2, 24, 0)
# define g_malloc0_n(x, y) g_malloc0((x) * (y))
#endif

#include "resource.h"

gpointer        typelib_random_buffer(gpointer buffer, gsize size);
gpointer        typelib_get_buffer(gpointer *buffer, gsize size);
gchar *         typelib_get_pathname(gchar **pathname);
gulong          typelib_get_integer(void);
gulong          typelib_get_integer_range(guint32 start, guint32 end);
void            typelib_clear_buffer(gpointer buffer);
gulong          typelib_get_integer_selection(guint count, ...);
gulong          typelib_get_integer_mask(gulong mask);

enum {
    IOV_NONE           = 0,
};

gpointer        typelib_get_iovec(gpointer *iov, gint *count, guint flags);
void            typelib_clear_iovec(gpointer iovec, gint count, guint flags);

// Vmas.
enum {
    VMA_NONE            = 0,
    VMA_DEBUG           = 1 << 0,   // Extra debugging requested.
    VMA_HUGE            = 1 << 1,   // Possibly a HUGE_PAGE mapping.
    VMA_SHM             = 1 << 2,   // Mapped via shmat(), not mmap, etc.
};

    // Main.
    void            typelib_vma_new(syscall_fuzzer_t *this, guintptr address, gsize size, gint flags);
    void            typelib_vma_stale(syscall_fuzzer_t *this, guintptr address);
    guintptr        typelib_get_vma(syscall_fuzzer_t *this, guintptr *address, gsize *size);

#else
# warning typelib.h included twice
#endif

