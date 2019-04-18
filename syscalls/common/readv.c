#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Read or write data into multiple buffers.
// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
// XXX FIXME
SYSFUZZ(readv, SYS_readv, SYS_DISABLED, CLONE_DEFAULT, 0)
{
    return 0;
}

