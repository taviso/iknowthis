#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <linux/net.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

#ifndef SYS_RECVMMSG
# define SYS_RECVMMSG 19
#endif

#ifndef SYS_ACCEPT4
# define SYS_ACCEPT4 18
#endif

#ifndef SYS_SENDMMSG
# define SYS_SENDMMSG 20
#endif

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 010000000
#endif

#ifndef SOCK_NONBLOCK
# define SOCK_NONBLOCK 000000004
#endif

// Callback for typelib_add_resource().
static gboolean destroy_open_file(guintptr fd)
{
    return syscall(__NR_close, fd) != -1;
}

// Socket system calls.
// XXX: Think of a way to give these separate fuzzers.
SYSFUZZ(socketcall, __NR_socketcall, SYS_NONE, CLONE_DEFAULT, 1000)
{
    gint        fd;
    gint        i;
    gint        retcode;
    guintptr    socketcall_args[8];

    // Initialise arguments.
    memset(socketcall_args, 0, sizeof socketcall_args);

    // Choose a socket operation.
    switch (typelib_get_integer_selection(19, SYS_SOCKET,
                                              SYS_BIND,
                                              SYS_CONNECT,
                                              SYS_LISTEN,
                                              SYS_ACCEPT,
                                              SYS_GETSOCKNAME,
                                              SYS_GETPEERNAME,
                                              SYS_SOCKETPAIR,
                                              SYS_SEND,
                                              SYS_RECV,
                                              SYS_SENDTO,
                                              SYS_RECVFROM,
                                              SYS_SHUTDOWN,
                                              SYS_SETSOCKOPT,
                                              SYS_GETSOCKOPT,
                                              SYS_SENDMSG,
                                              SYS_RECVMSG,
                                              SYS_ACCEPT4,
                                              SYS_RECVMMSG,
                                              SYS_SENDMMSG)) {
        case SYS_SOCKET:    // Create an endpoint for communication.
            // Install arguments.
            socketcall_args[0]  = typelib_get_integer_range(0, 32);     // int domain
            socketcall_args[1]  = typelib_get_integer_range(0, 16);     // int type
            socketcall_args[2]  = typelib_get_integer_selection(1, 0);  // int protocol

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,                     // int
                                       SYS_SOCKET,                                      // int call
                                       socketcall_args);                                // unsigned long *args

            // Check for new socket.
            if (retcode == ESUCCESS) {
                typelib_add_resource(this, fd, RES_FILE, RF_NONE, destroy_open_file);
            }

            return retcode;

        case SYS_BIND:      // Bind a name to a socket.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);   // int sockfd
            socketcall_args[2]  = typelib_get_integer_range(0, 64);                      // socklen_t addrlen

            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);                // const struct sockaddr *addr

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,                      // int
                                       SYS_BIND,                                         // int call
                                       socketcall_args);                                 // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));

            return retcode;
        case SYS_CONNECT:       // Initiate a connection on a socket.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);   // int sockfd
            socketcall_args[2]  = g_random_int_range(0, 64);                             // socklen_t addrlen
            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);                // const struct sockaddr *addr

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,                      // int
                                       SYS_CONNECT,                                      // int call
                                       socketcall_args);                                 // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));

            return retcode;

        case SYS_LISTEN:        // Listen for connections on a socket.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);   // int sockfd
            socketcall_args[1]  = g_random_int_range(0, 64);                             // socklen_t addrlen
            socketcall_args[2]  = g_random_int_range(0, 1024);                           // socklen_t addrlen

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,                      // int
                                       SYS_LISTEN,                                       // int call
                                       socketcall_args);                                 // unsigned long *args

            return retcode;

        case SYS_ACCEPT:        // Accept a connection on a socket.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);   // int sockfd
            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);                // struct sockaddr *addr
            typelib_get_buffer((void **) &socketcall_args[2], PAGE_SIZE);                // socklen_t *addrlen

            // Make call.
            retcode = spawn_syscall_lwp(this, NULL, __NR_socketcall,                     // int
                                        SYS_ACCEPT,                                      // int call
                                        socketcall_args);                                // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[2]));

            return retcode;
        case SYS_GETSOCKNAME:   // Get socket name.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);                                  // int sockfd
            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);                // struct sockaddr *addr
            typelib_get_buffer((void **) &socketcall_args[2], PAGE_SIZE);                // socklen_t *addrlen

            // Make call.
            retcode = spawn_syscall_lwp(this, NULL, __NR_socketcall,                     // int
                                        SYS_GETSOCKNAME,                                 // int call
                                        socketcall_args);                                // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[2]));

            return retcode;

        case SYS_GETPEERNAME:   // Get name of connected peer socket.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);   // int sockfd

            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);                // struct sockaddr *addr
            typelib_get_buffer((void **) &socketcall_args[2], PAGE_SIZE);                // socklen_t *addrlen

            // Make call.
            retcode = spawn_syscall_lwp(this, NULL, __NR_socketcall,                     // int
                                        SYS_GETPEERNAME,                                 // int call
                                        socketcall_args);                                // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[2]));

            return retcode;

        case SYS_SOCKETPAIR:    // Create a pair of connected sockets.
            // Install arguments.
            socketcall_args[0]  = typelib_get_integer_range(0, 32);     // int domain
            socketcall_args[1]  = typelib_get_integer_range(0, 16);     // int type
            socketcall_args[2]  = typelib_get_integer_selection(1, 0);  // int protocol

            typelib_get_buffer((void **) &socketcall_args[3], PAGE_SIZE);// int sv[2]

            // Possibly add some options.
            socketcall_args[1] |= (g_random_int() & g_random_int() & g_random_int());

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,     // int
                                       SYS_SOCKETPAIR,                  // int call
                                       socketcall_args);                // unsigned long *args

            // Check for new socket.
            if (retcode == ESUCCESS) {
                gint    *sv = GUINT_TO_POINTER(socketcall_args[3]);

                // Record the socketpair.
                typelib_add_resource(this, sv[0], RES_FILE, RF_NONE, destroy_open_file);
                typelib_add_resource(this, sv[1], RES_FILE, RF_NONE, destroy_open_file);
            }

            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[3]));

            return retcode;

        case SYS_SEND:          // Send a message on a socket.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);  // int sockfd
            socketcall_args[2]  = typelib_get_integer_range(0, PAGE_SIZE);              // size_t len
            socketcall_args[3]  = typelib_get_integer_mask(MSG_CONFIRM
                                                         | MSG_DONTROUTE
                                                         | MSG_DONTWAIT
                                                         | MSG_EOR
                                                         | MSG_MORE
                                                         | MSG_NOSIGNAL
                                                         | MSG_OOB);

            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);

            // Make call.
            retcode = spawn_syscall_lwp(this, NULL, __NR_socketcall, // int
                                       SYS_SEND,                     // int call
                                       socketcall_args);             // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));

            return retcode;
        case SYS_RECV:          // Receive a message from a socket.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);  // int sockfd
            socketcall_args[2]  = typelib_get_integer_range(0, PAGE_SIZE);  // size_t len
            socketcall_args[3]  = typelib_get_integer_mask(MSG_CONFIRM
                                                         | MSG_DONTROUTE
                                                         | MSG_DONTWAIT
                                                         | MSG_EOR
                                                         | MSG_MORE
                                                         | MSG_NOSIGNAL
                                                         | MSG_OOB);

            typelib_get_buffer((void **) &socketcall_args[1], PAGE_SIZE);

            // Make call.
            retcode = spawn_syscall_lwp(this, NULL, __NR_socketcall, // int
                                       SYS_RECV,                     // int call
                                       socketcall_args);             // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));

            return retcode;

        case SYS_SENDTO:        // Send a message on a socket.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);  // int sockfd
            socketcall_args[2]  = typelib_get_integer();            // size_t len
            socketcall_args[3]  = typelib_get_integer();            // int flags
            socketcall_args[5]  = g_random_int_range(0, 8192);      // socklen_t addrlen

            typelib_get_buffer((void **) &socketcall_args[1],       // void *buf
                               g_random_int_range(0, 8192));
            typelib_get_buffer((void **) &socketcall_args[4],       // const struct sockaddr *dest_addr
                               g_random_int_range(0, 8192));

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall, // int
                                        SYS_SENDTO,                 // int call
                                        socketcall_args);           // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[4]));

            return retcode;

        case SYS_RECVFROM:      // Receive a message from a socket.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);  // int sockfd
            socketcall_args[2]  = typelib_get_integer();            // size_t len
            socketcall_args[3]  = typelib_get_integer();            // int flags
            socketcall_args[5]  = g_random_int_range(0, 8192);      // socklen_t addrlen

            typelib_get_buffer((void **) &socketcall_args[1],       // void *buf
                               g_random_int_range(0, 8192));
            typelib_get_buffer((void **) &socketcall_args[4],       // struct sockaddr *dest_addr
                               g_random_int_range(0, 8192));

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall, // int
                                       SYS_SENDTO,                  // int call
                                       socketcall_args);            // unsigned long *args

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[4]));

            return retcode;

        case SYS_SHUTDOWN:      // Shut down part of a full-duplex connection.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int sockfd
            socketcall_args[2]  = g_random_int_range(0, 32);        // int how

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall, // int
                                        SYS_SHUTDOWN,               // int call
                                        socketcall_args);           // unsigned long *args

            return retcode;

        case SYS_SETSOCKOPT:    // Get and set options on sockets.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int sockfd
            socketcall_args[1]  = typelib_get_integer_range(0, 256);// int level
            socketcall_args[2]  = typelib_get_integer_range(0, 128);// int optname
            socketcall_args[4]  = typelib_get_integer_range(0, 64); // socklen_t optlen

            typelib_get_buffer((void **) &socketcall_args[3], PAGE_SIZE);

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall, // int
                                        SYS_SETSOCKOPT,             // int call
                                        socketcall_args);           // unsigned long

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[3]));

            return retcode;
        case SYS_GETSOCKOPT:    // Get and set options on sockets.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int sockfd
            socketcall_args[1]  = typelib_get_integer_range(0, 256);// int level
            socketcall_args[2]  = typelib_get_integer_range(0, 128);// int optname

            typelib_get_buffer((void **) &socketcall_args[3],       // const void *optval
                               g_random_int_range(0, 8192));

            typelib_get_buffer((void **) &socketcall_args[4],       // socklen_t *optlen
                               g_random_int_range(0, 32));

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall, // int
                                        SYS_GETSOCKOPT,             // int call
                                        socketcall_args);           // unsigned long

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[3]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[4]));

            return retcode;
        case SYS_SENDMSG:       // Send a message on a socket.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int s
            socketcall_args[2]  = typelib_get_integer();            // int flags

            typelib_get_buffer((void **) &socketcall_args[1],       // struct msghdr *msg,
                               g_random_int_range(0, 8192));

            // Make call.
            retcode = spawn_syscall_lwp(this,  &fd, __NR_socketcall,
                                        SYS_SENDMSG,
                                        socketcall_args);
            typelib_clear_buffer(socketcall_args[1]);
            return retcode;
        case SYS_RECVMSG:       // Receive a message from a socket.
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int s
            socketcall_args[2]  = typelib_get_integer();            // int flags

            typelib_get_buffer((void **) &socketcall_args[1],       // struct msghdr *msg,
                               g_random_int_range(0, 8192));

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,
                                        SYS_RECVMSG,
                                        socketcall_args);
            typelib_clear_buffer(socketcall_args[1]);
            return retcode;
        case SYS_ACCEPT4:       // Accept a connection on a socket.

            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int sockfd
            socketcall_args[3]  = typelib_get_integer();            // int flags

            typelib_get_buffer((void **) &socketcall_args[1],       // struct sockaddr *addr
                               g_random_int_range(0, 8192));

            typelib_get_buffer((void **) &socketcall_args[2],       // socklen_t *addrlen
                               g_random_int_range(0, 32));

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,  // int
                                        SYS_ACCEPT4,                 // int call
                                        socketcall_args);            // unsigned long

            // Clean up.
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[2]));

            return retcode;
        case SYS_RECVMMSG:
            // ssize_t recvmmsg(int socket, struct mmsghdr *mmsg, int vlen, int flags);
            // XXX: FIXME
            // Install arguments.
            socketcall_args[0]  = typelib_get_resource(this, NULL, RES_FILE, RF_NONE);             // int s
            socketcall_args[2]  = 1;                                // int vlen;
            socketcall_args[3]  = typelib_get_integer();            // int flags

            typelib_get_buffer((void **) &socketcall_args[1],       // struct msghdr *msg,
                               g_random_int_range(0, 8192));

            // Make call.
            retcode = spawn_syscall_lwp(this, &fd, __NR_socketcall,
                                        SYS_RECVMMSG,
                                        socketcall_args);

            typelib_clear_buffer(GUINT_TO_POINTER(socketcall_args[1]));
            return retcode;
        case SYS_SENDMMSG:
            // We don't need this because the kernel developers finally
            // realised that socketcall is super ugly, and senddmsg is
            // available directly.
        default:
            // Random number and args.
            for (i = 0; i < 8; i++) {
                socketcall_args[i] = typelib_get_integer();
            }

            return spawn_syscall_lwp(this, NULL, __NR_socketcall,
                                     typelib_get_integer(),
                                     socketcall_args);
    }
}

