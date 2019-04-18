#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "maps.h"

gboolean maps_contains_address(GSList *maps, guintptr address)
{
    while (maps) {
        struct map *map = maps->data;

        maps = maps->next;

        if (map->start <= address && address <= map->end) {
            g_debug("found %#lx - %#lx, %c%c%c%c",
                    map->start,
                    map->end,
                    map->perms.r,
                    map->perms.w,
                    map->perms.x,
                    map->perms.p);
            return true;
        }
    }

    return false;
}

static gint maps_full_compare(gconstpointer a, gconstpointer b)
{
    const struct map *x = a;
    const struct map *y = b;

    if (x->start != y->start
        || x->end != y->end
        || x->perms.r != y->perms.r
        || x->perms.w != y->perms.w
        || x->perms.x != y->perms.x
        || x->perms.p != y->perms.p
        || x->offset != y->offset
        || x->device.major != y->device.major
        || x->device.minor != y->device.minor
        || x->inode != y->inode
        || g_strcmp0(x->pathname, y->pathname) != 0)
        return 1;
    return 0;
}

#if 0
static gint maps_addr_compare(gconstpointer a, gconstpointer b)
{
    return ((const struct map *)(a))->start
         - ((const struct map *)(b))->start;
}
#endif

void maps_print_diff(GSList *before, GSList *after)
{
    GSList *i;

    // Find the changes / deletions
    for (i = before; i; i = i->next) {
        struct map *m = i->data;
        if (!g_slist_find_custom(after,
                                 i->data,
                                 maps_full_compare)) {

            g_debug("Map was modified or removed: %#" G_GINTPTR_MODIFIER "x-%#" G_GINTPTR_MODIFIER "x", m->start, m->end);
        }
    }

    // Find the additions
    for (i = after; i; i = i->next) {
        struct map *m = i->data;
        if (!g_slist_find_custom(before,
                                 i->data,
                                 maps_full_compare)) {
            g_debug("Map was added or split: %#" G_GINTPTR_MODIFIER "x-%#" G_GINTPTR_MODIFIER "x", m->start, m->end);
        }
    }

    return;
}

gboolean maps_sanity_check(GSList *maps)
{
    GSList     *node;

    // 1. Check each map makes sense.
    for (node = maps; node; node = node->next) {
        struct map *map = node->data;

        // Page aligned.
        g_assert_cmpint(map->start & (PAGE_SIZE - 1), ==, 0);
        g_assert_cmpint(map->end & (PAGE_SIZE - 1), ==, 0);

        // In userspace.
        g_assert_cmpint(map->start, <=, 0xC0000000);
        g_assert_cmpint(map->end, <=, 0xC0000000);

        // Not at NULL (mmap_min_addr)
        g_assert_cmpint(map->start, >, 0);

        // Size makes sense.
        g_assert_cmpint(map->start, <, map->end);
        g_assert_cmpint(map->end, >, map->start);
    }

    // doesnt overlap, etc.
    return true;
}

void maps_destroy_list(GSList *maps)
{
    GSList     *node;

    // Destroy the elements;
    for (node = maps; node; node = node->next) {
        g_free(node->data);
    }

    // Clean up the list.
    g_slist_free(maps);

    return;
}

gchar * maps_get_entry(guintptr address)
{
    gchar        *contents  = NULL;
    gchar       **split     = NULL;
    gchar        *entry     = NULL;
    guint         i;

    // Read /proc/self/maps.
    if (g_file_get_contents("/proc/self/maps", &contents, NULL, NULL) == false) {
        g_critical("failed to read maps file");
    }

    // Split into individual maps.
    if ((split = g_strsplit(contents, "\n", -1)) == NULL) {
        g_critical("failed to split maps contents");
    }

    // Parse each split line.
    for (i = 0; i < g_strv_length(split); i++) {
        guintptr start  = 0;
        guintptr end    = 0;

        // XXX: Note that it's possible for an address to appear more than
        //      once in maps,as it's possible to get duplicate zero length
        //      maps.

        // Parse map.
        if (sscanf(split[i], "%" G_GINTPTR_MODIFIER "x-%" G_GINTPTR_MODIFIER "x %*c%*c%*c%*c %*x %*x:%*x %*u %*[^\n]", &start, &end) == 2) {
            // Check for match with address.
            if (start <= address && end >= address) {
                // Looks good, we found a match.
                entry = g_strdup(split[i]);
                break;
            }
        } else {
            // Malformed.
            break;
        }
    }

    // Make sure that worked
    if (entry == NULL) {
        //g_warning("failed to find vma %#x, this is a bug (split len is %u)", address, g_strv_length(split));
        //g_debug("------");
        //g_debug("%s", contents);
        //g_debug("------");
    }

    // Clean up.
    g_free(contents);
    g_strfreev(split);


    return entry;
}

GSList *maps_take_snapshot(void)
{
    gchar        *contents  = NULL;
    gchar       **split     = NULL;
    GSList       *snapshot  = NULL;
    guint         i;

    // Read /proc/self/maps.
    if (g_file_get_contents("/proc/self/maps", &contents, NULL, NULL) == false) {
        g_critical("failed to read maps file");
    }

    // Split into individual maps.
    if ((split = g_strsplit(contents, "\n", -1)) == NULL) {
        g_critical("failed to split maps contents");
    }

    // Parse each split line.
    for (i = 0; i < g_strv_length(split) - 1; i++) {
        struct map *record = g_malloc0(sizeof(struct map) + strlen(split[i]));

        // XXX: Note that it's possible for an address to appear more than
        //      once in maps,as it's possible to get duplicate zero length
        //      maps.

        // Parse map.
        // 00654000-00672000 r-xp 00000000 fd:01 19824      /lib/ld-2.12.so
        if (sscanf(split[i], "%" G_GINTPTR_MODIFIER "x-%" G_GINTPTR_MODIFIER "x %c%c%c%c %x %hhx:%hhx %u %[^\n]",
                             &record->start,
                             &record->end,
                             &record->perms.r,
                             &record->perms.w,
                             &record->perms.x,
                             &record->perms.p,
                             &record->offset,
                             &record->device.major,
                             &record->device.minor,
                             &record->inode,
                             record->pathname) >= 10) {
            //g_message("successfully parsed map line %s", split[i]);
            // Add to list
            snapshot = g_slist_append(snapshot, record);
        } else {
            //g_message("unable to parse this map line: %s", split[i]);
            abort();
        }
    }

    // Clean up.7
    g_free(contents);
    g_strfreev(split);
    return snapshot;
}

void maps_pretty_print_snapshot(GSList *snapshot)
{
    while (snapshot) {
        struct map *data = snapshot->data;

        g_message("%08" G_GINTPTR_MODIFIER "x-%08" G_GINTPTR_MODIFIER "x %c%c%c%c %08x %hhx:%hhx %10u %s",
                  data->start,
                  data->end,
                  data->perms.r,
                  data->perms.w,
                  data->perms.x,
                  data->perms.p,
                  data->offset,
                  data->device.major,
                  data->device.minor,
                  data->inode,
                  data->pathname);

        snapshot = snapshot->next;
    }
}

#ifndef MAP_UNINITIALIZED
# define MAP_UNINITIALIZED 0x4000000
#endif
#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_STACK
# define MAP_STACK 0
#endif

// Clean out unrecognised flags to make debugging easier.
guint maps_sanitise_flags(guint flags)
{
    return flags & (MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS |
                    MAP_UNINITIALIZED | MAP_GROWSDOWN | MAP_DENYWRITE |
                    MAP_EXECUTABLE | MAP_LOCKED | MAP_NORESERVE |
                    MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB);
}

void maps_decode_flags(guint flags)
{
    g_message("Decoding mmap() flags %#x...", flags);

    if (flags & MAP_SHARED) g_message("\tMAP_SHARED");
    if (flags & MAP_PRIVATE) g_message("\tMAP_PRIVATE");
    if (flags & MAP_FIXED) g_message("\tMAP_FIXED");
    if (flags & MAP_ANONYMOUS) g_message("\tMAP_ANONYMOUS");
    if (flags & MAP_UNINITIALIZED) g_message("\tMAP_UNINITIALIZED");
    if (flags & MAP_GROWSDOWN) g_message("\tMAP_GROWSDOWN");
    if (flags & MAP_DENYWRITE) g_message("\tMAP_DENYWRITE");
    if (flags & MAP_EXECUTABLE) g_message("\tMAP_EXECUTABLE");
    if (flags & MAP_LOCKED) g_message("\tMAP_LOCKED");
    if (flags & MAP_NORESERVE) g_message("\tMAP_NORESERVE");
    if (flags & MAP_POPULATE) g_message("\tMAP_POPULATE");
    if (flags & MAP_NONBLOCK) g_message("\tMAP_NONBLOCK");
    if (flags & MAP_STACK) g_message("\tMAP_STACK");
    if (flags & MAP_HUGETLB) g_message("\tMAP_HUGETLB");

    flags &= ~(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS |
               MAP_UNINITIALIZED | MAP_GROWSDOWN | MAP_DENYWRITE |
               MAP_EXECUTABLE | MAP_LOCKED | MAP_NORESERVE |
               MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB);

    g_message("Unrecognised flags: %#x", flags);

    return;
}

// There must be only one notable difference.
bool maps_compare_snapshots(GSList *before,
                            GSList *after,
                            guintptr address,
                            gsize size,
                            guint flags,
                            guint prot,
                            void *important)
{
    GSList *snapshot    = maps_take_snapshot();
    GSList *i           = snapshot;

    if (GUINT_TO_POINTER(address) == MAP_FAILED) {
        maps_destroy_list(snapshot);
        return true;
    }

    g_assert_cmpint(address & (PAGE_SIZE - 1), ==, 0);

    // First, round size up to PAGE_SIZE
    size    = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

    // Adjust address if this grows down.
    address = flags & MAP_GROWSDOWN 
                ? address + PAGE_SIZE
                : address;

    // And adjust the address accordingly.
    size    = flags & MAP_GROWSDOWN
                ? size - PAGE_SIZE
                : size;

    // Scan for this map.
    for (i = snapshot; i; i = i->next) {
        struct map *data = i->data;

        if (address >= data->start && address + size <= data->end) {
            if (flags & MAP_HUGETLB) {
                g_assert(strstr(data->pathname, "anon_hugepage"));
            } else {
                g_assert(!strstr(data->pathname, "anon_hugepage"));
            }

            maps_destroy_list(snapshot);
            return true;
        }
    }
    G_BREAKPOINT();
    return true;
}
