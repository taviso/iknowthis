#ifndef __COMPAT_H
#define __COMPAT_H


// Support for older Linux distribution

#if !GLIB_CHECK_VERSION(2, 14, 0)
    typedef gint64 goffset;
#endif

#ifndef SHM_EXEC
# define SHM_EXEC 0100000 /* execution access */
#endif

#ifndef CTL_PROC
# define CTL_PROC 4
#endif

#ifndef CTL_ARLAN
# define CTL_ARLAN 254
#endif

#ifndef CTL_S390DBF
# define CTL_S390DBF 5677
#endif

#ifndef CTL_SUNRPC
# define CTL_SUNRPC 7249
#endif

#ifndef CTL_PM
# define CTL_PM 9899
#endif

#ifndef CTL_FRV
# define CTL_FRV 9898
#endif

#endif
