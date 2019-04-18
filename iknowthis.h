#ifndef __IKNOWTHIS_H
#define __IKNOWTHIS_H
#pragma once

#define SECRET 0x5261576245725279ULL

void    create_dirty_pages(void);
gint    spawn_syscall_lwp(syscall_fuzzer_t *this, glong *status, glong sysno, ...);
guint   increment_process_count(void);
guint   get_process_count(void);
void    clear_shared_segments(uid_t owner);
void    create_process_shmid(void);

#else
# warning iknowthis.h included twice
#endif
