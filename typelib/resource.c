#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"

// Routines to manage generic resource descriptors that don't need any special
// management. For example, aio contexts, key serials, etc. If you need to
// manage a new type of resource, add it to the enum in resource.h, then just
// write a callback.

typedef struct {
    guintptr            resource;                   // Resource descriptor.
    guint               flags;                      // Any flags to modify typelib behaviour.
    GSList             *trace;                      // List of callers.
    destroy_callback_t  destroy;                    // Callback to destroy this resource.
} resource_t;

// Array of linked lists, one for each resource type.
static GSList *type_resource_list[kNumResources];

// How many descriptors should I remember?
#define MAX_RESOURCE_COUNT 512

// Learn a new one, saving into a linked list.
gboolean typelib_add_resource(syscall_fuzzer_t *this, guintptr descriptor, guint type, guint flags, destroy_callback_t destroy)
{
    resource_t  *record = g_new(resource_t, 1);
    GSList      *node   = NULL;
    GSList     **list   = &type_resource_list[type];
    guint        count  = 0;

    g_assert_cmpint(type, <, kNumResources);

    record->resource    = descriptor;
    record->flags       = flags;
    record->trace       = g_slist_append(NULL, this);
    record->destroy     = destroy;
    *list               = g_slist_append(*list, record);
    count               = g_slist_length(*list);

    // Possibly choose a random node to release if I've exhausted my quota.
    if (count > MAX_RESOURCE_COUNT) {
        node    = g_slist_nth(*list, g_random_int_range(0, count));
        record  = node->data;

        if (record->destroy(record->resource) != true) {
            g_warning("destroy callback for fuzzer %s returned false, possible resource leak.", this->name);
        }

        // Clear trace list.
        g_slist_free(record->trace);

        // Release data.
        g_free(record);

        // Remove from list.
        *list = g_slist_delete_link(*list, node);
    }

    g_assert_cmpint(g_slist_length(*list), <=, MAX_RESOURCE_COUNT);
    g_assert_cmpint(g_slist_length(*list), >=, 1);

    return true;
}

// Return a random entry from the list.
guintptr typelib_get_resource(syscall_fuzzer_t *this, guintptr *ret, guint type, guint flags)
{
    resource_t  *record = NULL;
    GSList      *node   = NULL;
    GSList     **list   = &type_resource_list[type];
    guint        len    = 0;
    guintptr     desc   = 0;

    // Check I have some available.
    if ((len = g_slist_length(*list))) {
        node   = g_slist_nth(*list, g_random_int_range(0, len));
        record = node->data;
        desc   = record->resource;

        // Check if caller wants me to remove this resource.
        if (flags & RF_TAKEOWNERSHIP) {
            *list = g_slist_delete_link(*list, node);

            g_slist_free(record->trace);
            g_free(record);

            return ret ? *ret = desc : desc;
        }
    } else {
        // I don't know how else this can fail.
        g_assert_cmpint(len, ==, 0);

        // Use an invalid descriptor.
        return -1;
    }

    // Record a usage trace for debugging.
    record->trace = g_slist_append(record->trace, this);

    // Return descriptor to caller.
    return ret ? *ret = record->resource : record->resource;
}
