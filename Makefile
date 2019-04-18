# iknowthis requires the glib2, and clearsilver packages.
#
#    Fedora:    yum install clearsilver-devel glib2-devel zlib-devel libmicrohttpd-devel
#    Debian:    apt-get install clearsilver-dev libglib2.0-dev libmicrohttpd-dev
##

CFLAGS      =-Wall -Wno-multichar -pipe -O0 -ggdb3 -fno-strict-aliasing `pkg-config --cflags libmicrohttpd,glib-2.0` -std=gnu99
LDFLAGS     =$(CFLAGS) `pkg-config --libs libmicrohttpd,glib-2.0` -lneo_cs -lneo_cgi -lneo_utl -lz -Wl,-z,now
CPPFLAGS    =-I. -Itypelib -I/usr/include/ClearSilver -I/usr/local/include/ClearSilver
ARCH       ?=$(shell uname -m)
OS         ?=$(shell uname -s)

# This glob matches all source files in the syscalls subdirectory.
SYSCALLS    = $(patsubst %.c,%.o,$(wildcard syscalls/$(OS)/$(ARCH)/*.c))

# Default rule.
all:        iknowthis

iknowthis:  $(SYSCALLS) iknowthis.o base.o buffer.o typelib/pathname.o \
            typelib/resource.o vma.o proc.o report.o uid.o lwp.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o syscalls/*/*/*.o iknowthis core.* *.core core typelib/*.o
