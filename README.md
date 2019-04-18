# iknowthis Linux SystemCall Fuzzer
-------------------------------------------------

> NOTE: This is a very old fuzzer, it was used to find some pretty important
> vulnerabilities back in 2009-2010, but has since been superseded by other
> fuzzers like syzkaller and trinity.
>
> Among many interesting discoveries, the most important was perhaps
> CVE-2009-2692, which was later found in the shadow brokers release as the
> EXACTCHANGE exploit.
>
> It is included here for historical reference, but is not supported.
>
> (Requires glib2.0-dev, clearsilver-dev, libmicrohttpd-dev)

iknowthis is a fuzz testing framework for Linux system calls. It is designed to
make system calls in random order, with random parameters in order to spot
subtle kernel bugs.

In order to get good coverage, each system call is annotated with a prototype,
and optionally a simple routine to manage any resources that may have been
created (sockets, file descriptors, etc.). These resources are then handed to
other system calls, in order to try and reach some pathological state of
operation.

Here is a trivial example of a fuzzer:

```c
// Check real user’s permissions for a file.
SYSFUZZ(access, __NR_access, SYS_NONE, CLONE_DEFAULT, 0)
{
    gchar   *pathname;
    gint     retcode;

    retcode = spawn_syscall_lwp(this, NULL, __NR_access,                                            // int
                                typelib_get_pathname(&pathname),                                    // const char *pathname
                                typelib_get_integer_mask(R_OK | W_OK | X_OK | F_OK));               // int mode

    g_free(pathname);
    return retcode;
}
```

Typelib is a set of routines to manage common kernel parameters.
`spawn_syscall_lwp()` is a syscall invokation routine that tries to isolate our
main process from any damage by executing it in a new lwp. If you're certain
that a system call can never timeout or damage us, then you can use a faster
alternative.

I've used glib for common data structures, so copied their naming convention
where appropriate.

* Making a fuzzer
* Using and improving typelib
* Debugging

I usually run iknowthis in a virtual machine, for easier debugging, you can try something like this:

`$ while true; do (sleep 1h ; sudo killall -9 iknowthis) & sudo ./iknowthis --dangerous; kill %1; done`
