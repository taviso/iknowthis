#include <glib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

typedef struct {
    gpointer    address;
    gsize       size;
} metadata_t;

// Quick heap management.
static GSList *buffer_allocation_list;

guint typelib_tracked_buffers()
{
    return g_slist_length(buffer_allocation_list);
}

// Randomise the contents of buffer.
gpointer typelib_random_buffer(gpointer buffer, gsize size)
{
    static int randfd;

    void __constructor init(void)
    {
        // Open static descriptor to /dev/urandom.
        randfd = open("/dev/urandom", O_RDONLY, 0);
    }

    void __destructor fini(void)
    {
        // Called automatically on program completion.
        close(randfd);
    }

    // At this point we should have an open fd.
    g_assert_cmpint(randfd, >=, 0);

    // Try to randomise the entire contents, failure isn't important.
    read(randfd, buffer, size);

    return buffer;
}

// Return a pointer to a guarded buffer.
gpointer typelib_get_buffer(gpointer *buffer, gsize size)
{
    gsize       totalsize;
    gpointer    guardbuf;
    metadata_t  *metadata;

    // Round up size to the next PAGE_SIZE
    totalsize = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

    // Add one page to be a guard page
    totalsize = totalsize + PAGE_SIZE;

    // Allocate
    guardbuf = mmap(NULL,
                    totalsize,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANON | MAP_PRIVATE,
                    -1,
                    0);

    // Check if that worked.
    if (guardbuf == MAP_FAILED) {
        g_error("memory allocation failed, %m");
    }

    // mprotect the last page
    mprotect(guardbuf + totalsize - PAGE_SIZE, PAGE_SIZE, PROT_NONE);

    // Return pointer to the Size requested before the guardpage.
    if (buffer) {
        *buffer = guardbuf + totalsize - PAGE_SIZE - size;
    }

    // Record this allocation.
    metadata            = g_new(metadata_t, 1);
    metadata->address   = guardbuf;
    metadata->size      = totalsize;

    buffer_allocation_list = g_slist_append(buffer_allocation_list, metadata);

    // g_debug("guarded %u byte buffer mapped at @%p", size, *buffer);

    // Fill buffer with random junk.
    return typelib_random_buffer(guardbuf + totalsize - PAGE_SIZE - size, size);
}

// Clean up an allocated buffer.
void typelib_clear_buffer(gpointer buffer)
{
    guint      *ptr;
    metadata_t *data;

    // Compare routine to search metadata
    gint metadata_compare_callback(gconstpointer a, gconstpointer b)
    {
        return ((metadata_t *)(a))->address
             - ((metadata_t *)(b))->address;
    }

    // Fine, just ignore it.
    if (buffer == NULL) {
        return;
    }

    // Calculate the start address of buffer.
    ptr  = GUINT_TO_POINTER(GPOINTER_TO_SIZE(buffer) & ~(PAGE_SIZE - 1));

    // Scan the allocation list to find it.
    data = g_slist_find_custom(buffer_allocation_list, &ptr, metadata_compare_callback)->data;

    // Scan it for secret value to check for leaks.
    // XXX: TODO

    // Remove from my records.
    buffer_allocation_list = g_slist_remove(buffer_allocation_list, data);

    // Calculate the actual size.
    munmap(data->address, data->size);

    g_free(data);
    return;
}

