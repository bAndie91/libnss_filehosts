# Makefile for libnss-gw-name

CC = gcc
prefix = /usr
exec_prefix = ${prefix}
BITSOFS=
libprefix = ${exec_prefix}/lib$(BITSOFS)
DESTDIR=
OBJSUFFIX=$(BITSOFS).o
OBJECTS=libnss_extip$(OBJSUFFIX) 
SHARED_OBJECT = libnss_extip$(BITSOFS).so.2
INSTALL_NAME = libnss_extip.so.2
# This only works sometimes, give manually when needed:
BIT_CFLAGS = $(if $(BITSOFS),-m$(BITSOFS))
CFLAGS = $(BIT_CFLAGS) -g -O2 -Wall -Wpointer-arith
#CPPFLAGS = $(shell pkg-config --cflags libnl-3.0 libnl-route-3.0)
CPPFLAGS = $(shell pkg-config --cflags libnl-3.0)
#LIBS = $(shell pkg-config --libs libnl-3.0 libnl-route-3.0)
LIBS = $(shell pkg-config --libs libnl-3.0)
LDFLAGS = -shared -Wl,-soname,$(INSTALL_NAME) -Wl,-z,defs

all: $(SHARED_OBJECT)

$(SHARED_OBJECT): $(OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $(SHARED_OBJECT) $(OBJECTS) $(LIBS)
#	strip $(SHARED_OBJECT)
	chmod -x $(SHARED_OBJECT)
	ln -sf $(SHARED_OBJECT) libnss_extip$(BITSOFS).so

%$(OBJSUFFIX): %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c -o $@ $<

install:
	install -m755 -d $(DESTDIR)$(libprefix)/
	install -m644 $(SHARED_OBJECT) $(DESTDIR)$(libprefix)/$(INSTALL_NAME)

clean:
	rm -f $(OBJECTS)
	rm -f $(SHARED_OBJECT)

distclean: clean

.PHONY: all
