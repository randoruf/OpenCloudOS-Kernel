TOPDIR ?= ../..
SYSROOT ?= $(TOPDIR)/sysroot
BPFTOOL ?= $(SYSROOT)/bin/bootstrap/bpftool

CC ?= gcc
STATIC ?= 0
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

DNS_CFLAGS += -g -Wall -O2 -I. -Wno-pointer-sign -Wno-unused-value \
		  -Wno-incompatible-pointer-types-discards-qualifiers  \
		  -fno-asynchronous-unwind-tables -Wno-unknown-attributes \
		  -I$(SYSROOT)/include -I$(TOPDIR)/include/ -I$(TOPDIR)/include/uapi


SHARED_LDFLAGS += -L$(SYSROOT)/lib -lbpf
STATIC_LDFLAGS += -static $(SYSROOT)/lib/libbpf.a -lelf -lz

all: dns-cache

%.bpf.o: %.bpf.c
	$(CLANG)  -c $(DNS_CFLAGS) $<  -emit-llvm -o - | llc -march=bpf -filetype=obj -o $@
	$(LLVM_STRIP) -g $@
 

%.skel.h: %.bpf.o
	@$(BPFTOOL) gen skeleton $< name dns > $@

dns-cache: dns.skel.h dns.c
ifeq ($(STATIC),1)
	$(CC) $(CFLAGS) $(DNS_CFLAGS) $^ $(LDFLAGS) $(STATIC_LDFLAGS) -o $@
else
	$(CC) $(CFLAGS) $(DNS_CFLAGS) $^ $(LDFLAGS) $(SHARED_LDFLAGS) -o $@
endif

install:
	@echo
	cp -a dns-cache $(SYSROOT)/bin/

clean:
	rm -rf *.o *.skel.h dns-cache

.PHONY: clean
