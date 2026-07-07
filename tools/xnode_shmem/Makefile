# SPDX-License-Identifier: GPL-2.0
# Build against the in-tree uapi headers:
#   make -C tools/xnode_shmem
CFLAGS += -O2 -Wall -I../../usr/include -I../../include/uapi

consumer: consumer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f consumer

.PHONY: clean
