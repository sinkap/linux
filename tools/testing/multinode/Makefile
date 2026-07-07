# SPDX-License-Identifier: GPL-2.0
#
# Build the multinode functional test. Uses only the in-tree uapi
# headers and libc; links static so the binary can be the initramfs
# /init.
#
#   make KHDR=<path to installed uapi headers>
#
# KHDR defaults to the headers_install output of the kbuild tree.
# CXX can be overridden to cross-compile (e.g. aarch64-linux-gnu-g++),
# and BIN to name the output per arch.

KHDR ?= $(CURDIR)/../../../usr/include
BIN ?= multinode_test
STATIC ?= 1
CXXFLAGS += -O2 -Wall -std=c++17 -I$(KHDR) -I.
ifeq ($(STATIC),1)
LDFLAGS += -static
endif

$(BIN): multinode_test.cc common.h bpf_prog.h
	$(CXX) $(CXXFLAGS) -o $@ multinode_test.cc $(LDFLAGS)

clean:
	rm -f multinode_test multinode_test-*

.PHONY: clean
