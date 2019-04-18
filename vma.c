#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "maps.h"

// All pages mapped by fuzzers are stored in a linked list.
//
// Each new vma is associated with a linked list of actions that have occurred
// on it, along with a snapshot of how it looked at that time.
//
// This should allow us to recreate the life of a vma.

struct vma {
    union {
        guintptr    i;                          // Integer.
        gpointer    p;                          // Pointer.
    }        address;                       // Start address,
    gsize    size;                          // Size in bytes.
    gint     flags;                         // Any flags to modify typelib behaviour.
    GSList  *trace;                         // List of actions.
};

struct trace {
    syscall_fuzzer_t    *caller;            // Caller.
    time_t               timestamp;         // Timestamp when this action occurred.
    gchar               *map;               // /proc/pid/maps entry at time of call.
};

static GSList *memory_map_list;             // A record of mapped pages.

// How many should I remember?
#define MAX_MEMORY_MAPS 8

static struct trace *typelib_vma_trace(syscall_fuzzer_t *this, guintptr address);
static gint          typelib_vma_compare(gconstpointer a, gconstpointer b);
static void          typelib_vma_destroy(struct vma *map, gboolean unmap);
static void          typelib_vma_prettyprint(struct vma *vma);

// Learn about a new resource, saving into a linked list.
void typelib_vma_new(syscall_fuzzer_t *this, guintptr address, gsize size, gint flags)
{
    struct vma *vma  = g_malloc(sizeof *vma);

    // Create a new record.
    vma->address.i      = address;
    vma->size           = size;
    vma->flags          = flags;
    vma->trace          = g_slist_append(NULL, typelib_vma_trace(this, address));

    // Check if we should perform additional sanity checks.
    if (vma->flags & VMA_DEBUG) {
        g_debug("fuzzer %s created new debug vma %#" G_GINTPTR_MODIFIER  "x, size %#" G_GSIZE_MODIFIER "x", this->name, address, size);

        // Dump the new object.
        typelib_vma_prettyprint(vma);
    }

    // Record this new resource.
    memory_map_list = g_slist_append(memory_map_list, vma);

    // Check if I need to release one.
    if (g_slist_length(memory_map_list) > MAX_MEMORY_MAPS) {
        // I do, choose a random node to delete.
        GSList *node = g_slist_nth(memory_map_list, 
                                   g_random_int_range(0,
                                   g_slist_length(memory_map_list)));

        // Destroy resource.
        typelib_vma_destroy(node->data, true);

        // XXX: Note that this may have selected the resource I just added, so
        //      the pointer may not be valid after this.
        memset(&vma, 0, sizeof vma);

        // Delete from list.
        memory_map_list = g_slist_delete_link(memory_map_list, node);
    }

    g_assert_cmpint(g_slist_length(memory_map_list), <=, MAX_MEMORY_MAPS);
    g_assert_cmpint(g_slist_length(memory_map_list), >=, 1);

    return;
}

// Report that a resource has been destroyed and should be removed from the list.
// XXX: i also need moved, resized, etc, no?
void typelib_vma_stale(syscall_fuzzer_t *this, guintptr address)
{
    struct vma *vma;
    GSList     *node;

    g_assert(this);

    // Find in the list.
    node  = g_slist_find_custom(memory_map_list,
                                &address,
                                typelib_vma_compare);

    // Sanity checks.
    g_assert(node);
    g_assert(node->data);

    // Get the description out of list node.
    vma = node->data;

    // Check if debugging requested.
    if (vma->flags & VMA_DEBUG) {
        g_debug("fuzzer %s reports vma %#" G_GINTPTR_MODIFIER "x is stale.", this->name, address);

        // Show a trace.
        typelib_vma_prettyprint(vma);
    }

    // Remove from the list.
    memory_map_list = g_slist_delete_link(memory_map_list, node);

    // Destroy the record for this resource.
    typelib_vma_destroy(vma, false);

    return;
}

// Return a random entry from the list.
guintptr typelib_get_vma(syscall_fuzzer_t *this, guintptr *address, gsize *size)
{
    struct vma *vma;
    guint       len;

    // Sanity checks.
    g_assert(this);

    // Check I have some available.
    if ((len = g_slist_length(memory_map_list))) {
        // I do, Choose a random list element.
        GSList *node = g_slist_nth(memory_map_list, g_random_int_range(0, len));

        // Check it looks sane.
        g_assert(node);
        g_assert(node->data);

        // Grab the struct from list node.
        vma = node->data;
    } else {
        // I don't know how else this can fail.
        g_assert_cmpint(len, ==, 0);

        // Okay, use an invalid number.
        if (size) *size = 0;
        if (address) *address = GPOINTER_TO_UINT(MAP_FAILED);

        return GPOINTER_TO_UINT(MAP_FAILED);
    }

    // Must be at least one trace.
    g_assert(vma->trace);

    // Record trace for debugging.
    vma->trace = g_slist_append(vma->trace, typelib_vma_trace(this, vma->address.i));

    // Possibly return size.
    if (size)  *size = vma->size;
    if (address) *address = vma->address.i;

    // Finished.
    return vma->address.i;
}

// Return a pointer to a trace structure.
static struct trace *typelib_vma_trace(syscall_fuzzer_t *this, guintptr address)
{
    struct trace *trace = g_malloc0(sizeof *trace);

    g_assert(this);

    // Take a snapshot of the state of this resource.
    trace->caller       = this;
    trace->timestamp    = time(0);
#if 0
    // FIXME: Originally I had planned to save large amounts of debugging data
    // so that we can find where something first  happened and track it down,
    // but this is hard to make portable. I disabled this code while porting to
    // FreeBSD, but would like to enable it again.
    trace->map          = maps_get_entry(address);
#endif

    return trace;
}

// Clean up a released resource.
static void typelib_vma_destroy(struct vma *vma, gboolean unmapvma)
{
    // GFunc used to destroy trace list.
    void typelib_vma_destroy_trace(gpointer data, gpointer user)
    {
        struct trace *trace = data;
        g_free(trace->map);
        g_free(trace);
    }

    // Check if we should perform additional sanity checks.
    if (vma->flags & VMA_DEBUG) {
        g_debug("debug vma %#" G_GINTPTR_MODIFIER "x, size %#" G_GSIZE_MODIFIER "x is being destroyed", vma->address.i, vma->size);

        // Dump the new object.
        typelib_vma_prettyprint(vma);
    }

    // Release if requested.
    if (unmapvma && munmap(vma->address.p, vma->size) == -1) {
        if (vma->flags & VMA_HUGE) {
            while (munmap(vma->address.p, vma->size) == -1) {
                g_message("scanning for hugepage size, trying %#" G_GSIZE_MODIFIER "x...", vma->size);
                vma->size += PAGE_SIZE;
            }
        } else if (vma->flags & VMA_SHM) {
            if (shmdt(vma->address.p) == -1) {
                g_warning("failed to detach shm segment %p, %m", vma->address.p);
                typelib_vma_prettyprint(vma);
                abort();
            }
        } else {
            // Dump some debugging information.
            g_warning("failed unmap vma %#" G_GINTPTR_MODIFIER "x, %s", vma->address.i, custom_strerror_wrapper(errno));
            typelib_vma_prettyprint(vma);
            abort();
        }
    }

    // Clean up the element, start with the trace list elements.
    g_slist_foreach(vma->trace, typelib_vma_destroy_trace, NULL);

    // Clean up the list itself.
    g_slist_free(vma->trace);

    // And finally release the descriptor.
    g_free(vma);

    return;
}

// Dump the contents of a descriptor for debugging.
static void typelib_vma_prettyprint(struct vma *vma)
{
    GSList *node = vma->trace;
    gchar  *date = g_alloca(26);
    guint   i    = 0;

    g_debug("Dump of vma %#" G_GINTPTR_MODIFIER "x follows.", vma->address.i);
    g_debug("\tVMA Size:             %#" G_GSIZE_MODIFIER "x", vma->size);
    g_debug("\tTrace Length:         %u", g_slist_length(node));
    g_debug("\tFlags Set:            %u", vma->flags);
    g_debug("\tResource Object:      %p", vma);
    g_debug("\tTrace List Head:      %p", node);

    // Dump the trace.
    while (node) {
        struct trace *trace;

        trace = node->data;
        node  = node->next;

        // Read the timestamp.
        ctime_r(&trace->timestamp, date);

        g_debug("%3u. %s %s %s",
            i++,
            trace->caller->name,
            g_strchomp(date),
            trace->map);
    }
}

// GCompareFunc for file descriptors.
static gint typelib_vma_compare(gconstpointer a, gconstpointer b)
{
    return ((const struct vma *)(a))->address.i
        -  ((const struct vma *)(b))->address.i;
}
