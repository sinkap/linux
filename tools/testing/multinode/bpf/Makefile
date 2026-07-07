# SPDX-License-Identifier: GPL-2.0
#
# libbpf-based selftest for the parts of the multi-node work that need
# real (clang-compiled) BPF programs — currently the JIT-inserted arena
# cache clean. Builds a static binary + the BPF object; run both in a
# QEMU guest (see run.sh).
#
#   make KBUILD=<kbuild dir> LIBBPF=<libbpf.a>
#
# KBUILD must contain vmlinux (with BTF) and usr/include (headers_install).
# LIBBPF defaults to the in-tree tools/lib/bpf build.

KBUILD  ?= ../../../../.kbuild
LIBBPF  ?= ../../../lib/bpf/libbpf.a
LIBBPF_SRC := ../../../lib/bpf
BPFTOOL ?= bpftool
CLANG   ?= clang

CFLAGS  += -O2 -static -Iinc -I$(KBUILD)/usr/include
LDLIBS  += $(LIBBPF) -lelf -lz -lzstd

all: multinode_bpf

vmlinux.h:
	$(BPFTOOL) btf dump file $(KBUILD)/vmlinux format c > $@

inc/bpf/libbpf.h:
	mkdir -p inc/bpf && cp $(LIBBPF_SRC)/*.h inc/bpf/

multinode.bpf.o: multinode.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -I$(LIBBPF_SRC) \
		-c $< -o $@

multinode_bpf: multinode_bpf.c inc/bpf/libbpf.h multinode.bpf.o
	$(CC) $(CFLAGS) multinode_bpf.c $(LDLIBS) -o $@

clean:
	rm -f multinode_bpf multinode.bpf.o vmlinux.h
	rm -rf inc

.PHONY: all clean
