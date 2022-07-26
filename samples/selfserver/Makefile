export TOPDIR=$(shell pwd)
export SYSROOT=$(TOPDIR)/sysroot

all: bpftool prog

init:
	mkdir -p $(SYSROOT)

libbpf: init
	make -C lib/libbpf all
	make -C lib/libbpf install

bpftool: libbpf | init
	make -C tools/bpftool all
	make -C tools/bpftool install

prog: bpftool
	make -C src all
	make -C src install

clean:
	make -C src clean
	make -C lib/libbpf clean
	make -C tools/bpftool clean
	rm -rf $(SYSROOT)

.PHONY: libbpf bpftool init
