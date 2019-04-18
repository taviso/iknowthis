#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// Process trace.
// int ptrace(int request, pid_t pid, caddr_t addr, int data);
// XXX FIXME
SYSFUZZ(ptrace, SYS_ptrace, SYS_DISABLED, CLONE_DEFAULT, 1000)
{
    return 0;
}
