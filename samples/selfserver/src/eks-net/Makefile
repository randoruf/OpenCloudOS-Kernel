TOPDIR ?= ../..
SYSROOT ?= $(TOPDIR)/sysroot
BPFTOOL ?= $(SYSROOT)/bin/bootstrap/bpftool

CC ?= gcc
STATIC ?= 0
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

NET_CFLAGS += -g -I. -Wno-pointer-sign -Wno-unused-value -Wno-unknown-attributes \
		  -fno-asynchronous-unwind-tables -I$(SYSROOT)/include -I$(TOPDIR)/include/ \
		  -I$(TOPDIR)/include/uapi


SRCS := eksnet.c arg_parse.c net_utils.c
SHARED_LDFLAGS += -L$(SYSROOT)/lib -lbpf
STATIC_LDFLAGS += -static $(SYSROOT)/lib/libbpf.a -lelf -lz

all: eks-net

%.bpf.o: %.bpf.c
	$(CLANG) -O2 $(CFLAGS) -c $(NET_CFLAGS) $<  -emit-llvm -o - | llc -march=bpf -filetype=obj -o $@
	$(LLVM_STRIP) -g $@

%.skel.h: %.bpf.o
	@$(BPFTOOL) gen skeleton $< name eksnet > $@

eks-net: eksnet.skel.h
ifeq ($(STATIC),1)
	$(CC) $(CFLAGS) $(NET_CFLAGS) $(SRCS) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@
else
	$(CC) $(CFLAGS) $(NET_CFLAGS) $(SRCS) $(LDFLAGS) $(SHARED_LDFLAGS) -o $@
endif

install:
	@echo
	cp -a eks-net $(SYSROOT)/bin/

clean:
	rm -rf *.o *.skel.h eks-net

.PHONY: clean
