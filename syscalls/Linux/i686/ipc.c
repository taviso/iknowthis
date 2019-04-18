#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <linux/sem.h>
#include <sys/types.h>
#include <syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

int shmdt(const void *shmaddr);

#ifndef SEMOP
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define SEMTIMEDOP       4
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24
#endif

// int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth);
SYSFUZZ(ipc, __NR_ipc, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint        retcode;
    gpointer    sops;
    gpointer    buf;
    gpointer    msgp;
    gintptr     addr;
    gpointer    timeout;

    switch (typelib_get_integer_selection(12, SEMOP,
                                              SEMGET,
                                              SEMCTL,
                                              SEMTIMEDOP,
                                              MSGSND,
                                              MSGRCV,
                                              MSGGET,
                                              MSGCTL,
                                              SHMAT,
                                              SHMDT,
                                              SHMGET,
                                              SHMCTL)) {
        case SEMOP:
            // int semop(int semid, struct sembuf *sops, unsigned nsops);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SEMOP,
                                        typelib_get_integer(),
                                        typelib_get_buffer(&sops, g_random_int_range(0, PAGE_SIZE)),
                                        typelib_get_integer());

            typelib_clear_buffer(sops);

            return retcode;
        case SEMGET:
            // int semget(key_t key, int nsems, int semflg);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SEMGET,
                                        typelib_get_integer(),
                                        typelib_get_integer(),
                                        typelib_get_integer());

            return retcode;
        case SEMCTL:
            // int semctl(int semid, int semnum, int cmd, ...);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SEMCTL,
                                        typelib_get_integer(),
                                        typelib_get_integer(),
                                        typelib_get_integer());
            return retcode;
        case SEMTIMEDOP:
            // int semtimedop(int semid, struct sembuf *sops, unsigned nsops, struct timespec *timeout);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SEMTIMEDOP,
                                        typelib_get_integer(),
                                        typelib_get_buffer(&sops, g_random_int_range(0, PAGE_SIZE)),
                                        typelib_get_integer(),
                                        typelib_get_buffer(&timeout, g_random_int_range(0, PAGE_SIZE)));

            typelib_clear_buffer(sops);
            typelib_clear_buffer(timeout);
            return retcode;
        case MSGSND:
            // int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, MSGSND,
                                        typelib_get_integer(),
                                        typelib_get_buffer(&msgp, g_random_int_range(0, PAGE_SIZE)),
                                        typelib_get_integer(),
                                        typelib_get_integer());
            typelib_clear_buffer(msgp);
            return retcode;
        case MSGRCV:
            // ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, MSGRCV,
                                        typelib_get_integer(),
                                        typelib_get_buffer(&msgp, g_random_int_range(0, PAGE_SIZE)),
                                        typelib_get_integer(),
                                        typelib_get_integer());
            typelib_clear_buffer(msgp);
            return retcode;
        case MSGGET:
            // int msgget(key_t key, int msgflg);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, MSGGET,
                                        typelib_get_integer(),
                                        typelib_get_integer());
            return retcode;
        case MSGCTL:
            // int msgctl(int msqid, int cmd, struct msqid_ds *buf);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, MSGCTL,
                                        typelib_get_integer(),
                                        typelib_get_integer(),
                                        typelib_get_buffer(&msgp, g_random_int_range(0, PAGE_SIZE)));
            typelib_clear_buffer(msgp);
            return retcode;
        case SHMAT:
            // void *shmat(int shmid, const void *shmaddr, int shmflg);
            retcode = spawn_syscall_lwp(this, &addr, __NR_ipc, SHMAT,
                                        typelib_get_integer(),
                                        typelib_get_integer(),
                                        typelib_get_integer());

            // In the unlikely event that worked...
            if (retcode == ESUCCESS) {
                g_message("detaching %#x after successful shmat()", addr);
                shmdt(GINT_TO_POINTER(addr));
            }

            return retcode;
        case SHMDT:
            // int shmdt(const void *shmaddr);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SHMDT, typelib_get_integer());

            return retcode;
        case SHMGET:
            // int shmget(key_t key, size_t size, int shmflg);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SHMGET,
                                        typelib_get_integer(),
                                        typelib_get_integer(),
                                        typelib_get_integer());
            return retcode;
        case SHMCTL:
            // int shmctl(int shmid, int cmd, struct shmid_ds *buf);
            retcode = spawn_syscall_lwp(this, NULL, __NR_ipc, SHMCTL,
                                        typelib_get_integer(),
                                        typelib_get_integer(),
                                        typelib_get_buffer(&buf, g_random_int_range(0, PAGE_SIZE)));
            typelib_clear_buffer(buf);
            return retcode;
    }

    return spawn_syscall_lwp(this, NULL, __NR_ipc,
                             typelib_get_integer(),
                             typelib_get_integer(),
                             typelib_get_integer(),
                             typelib_get_integer(),
                             typelib_get_integer());
}
