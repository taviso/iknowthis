#ifndef __MAPS_H
#define __MAPS_H
#pragma once

// Approximate representation of map from proc(5) description.
struct map {
    guintptr    start;
    guintptr    end;
    struct {
        gchar   r;
        gchar   w;
        gchar   x;
        gchar   p;
    } perms;
    guint       offset;
    struct  {
    	guchar  major;
    	guchar  minor;
    } device;
    guint       inode;
    gchar       pathname[0];
};

gchar * maps_get_entry(guintptr address);

// Destroy a GSList previously returned by maps_get_list().
void        maps_destroy_list(GSList *maps);

#else
# warning maps.h included twice
#endif
