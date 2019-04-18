#ifndef __RESOURCE_H
#define __RESOURCE_H
#pragma once

enum {
    RES_AIOCTX,                     // An asynchronous i/o context.
    RES_AIOCB,                      // An asynchronous i/o request.
    RES_KEYSERIAL,                  // A keyring serial number.
    RES_FORK,                       // Forked child process.
    RES_FILE,                       // File descriptor.
    RES_SHMID,                      // Segment identifier.
    RES_SEMID,                      // Semaphore set.
    RES_MSGQ,                       // Message queue.
    kNumResources,
};

enum {
    RF_NONE             = 0,        // No flags, note that RF = Resource Flags
    RF_TAKEOWNERSHIP    = 1 << 0,   // Remove from list and let caller manage.
    RF_DEBUG            = 1 << 1,   // Enable additional debugging.
};

// Callback to destroy or release a resource.
typedef gboolean (* destroy_callback_t)(guintptr descriptor);

gboolean    typelib_add_resource(syscall_fuzzer_t *this, guintptr descriptor, guint type, guint flags, destroy_callback_t destroy);
guintptr    typelib_get_resource(syscall_fuzzer_t *this, guintptr *desc, guint type, guint flags);

#define VU(ptr) ((guintptr *)(ptr))

#else
# warning resource.h included twice
#endif
