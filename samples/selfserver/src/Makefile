TOPDIR ?= ..
SYSROOT ?= $(TOPDIR)/sysroot

all:
	make -C eks-net all
	make -C dns-cache all

install:
	make -C eks-net install
	make -C dns-cache install

clean:
	make -C eks-net clean
	make -C dns-cache clean

.PHONY: install clean
