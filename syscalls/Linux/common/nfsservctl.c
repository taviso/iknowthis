#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <glib.h>
#include <asm/unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NFSCTL_UGIDUPDATE 5
#define NFSCTL_GETFH 6
#define NFSCLNT_KEYMAX 32
#define NFSCLNT_ADDRMAX 16

#include <linux/nfsd/nfsfh.h>
#include <linux/nfsd/export.h>

#ifdef NFSCTL_VERSION
#include <linux/nfsd/syscall.h>

#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Syscall interface to kernel nfs daemon.
// long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);
SYSFUZZ(nfsservctl, __NR_nfsservctl, SYS_NONE, CLONE_DEFAULT, 0)
{
    gpointer            resp;
    glong               retcode;
    struct nfsctl_arg   argp = {
        .ca_version = typelib_get_integer_selection(1, NFSCTL_VERSION),
    };

    // Randomize the rest of the arguments.
    typelib_random_buffer(&argp.u, sizeof argp.u);

    retcode = spawn_syscall_lwp(this, NULL, __NR_nfsservctl,                                // long
                                typelib_get_integer_selection(8, NFSCTL_SVC,
                                                                 NFSCTL_ADDCLIENT,
                                                                 NFSCTL_DELCLIENT,
                                                                 NFSCTL_EXPORT,
                                                                 NFSCTL_UNEXPORT,
                                                                 NFSCTL_UGIDUPDATE,
                                                                 NFSCTL_GETFH,
                                                                 NFSCTL_GETFD,
                                                                 NFSCTL_GETFS),             // int cmd
                                &argp),                                                     // struct nfsctl_arg *argp
                                typelib_get_buffer(&resp, sizeof(union nfsctl_res));        // union nfsctl_res *resp

    typelib_clear_buffer(resp);
    return retcode;
}

#endif
