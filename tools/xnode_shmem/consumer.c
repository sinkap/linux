// SPDX-License-Identifier: GPL-2.0
/*
 * Demo consumer for a dma-buf backed BPF ringbuf produced on another,
 * non-cache-coherent node and consumed through the xnode_shmem window
 * driver (see Documentation/bpf/multi-node-bpf.md).
 *
 * Usage: consumer <data_size>
 *   data_size: the ringbuf data size (max_entries of the producer's
 *              map), a page-aligned power of two.
 *
 * The window layout is the dma-buf layout of the producer's map:
 *   page 0:  consumer_pos (only page mapped writable)
 *   page 1:  producer_pos
 *   page 2+: data, mapped twice back-to-back so records that wrap
 *            around the end of the buffer read as contiguous memory —
 *            the same trick the kernel and libbpf use.
 *
 * All mappings are write-combine (the driver enforces this), so plain
 * loads observe the producer's DRAM writes and the consumer_pos store
 * reaches DRAM without any cache maintenance. Acquire/release atomics
 * provide the ordering the BUSY-bit protocol needs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/xnode_shmem.h>

#define BPF_RINGBUF_BUSY_BIT	(1U << 31)
#define BPF_RINGBUF_DISCARD_BIT	(1U << 30)
#define BPF_RINGBUF_HDR_SZ	8

#define DEV_PATH "/dev/xnode_shmem"

static inline uint64_t load_acquire64(const volatile uint64_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline uint32_t load_acquire32(const volatile uint32_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void store_release64(volatile uint64_t *p, uint64_t v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static void process_sample(const void *sample, uint32_t len)
{
	printf("record: %u bytes\n", len);
	/* consume the payload here */
}

int main(int argc, char **argv)
{
	volatile uint64_t *consumer_pos, *producer_pos;
	long page_sz = sysconf(_SC_PAGESIZE);
	struct xnode_shmem_info info;
	unsigned long data_sz, mask;
	const uint8_t *data;
	void *reserved;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <data_size>\n", argv[0]);
		return 1;
	}
	data_sz = strtoul(argv[1], NULL, 0);
	if (!data_sz || (data_sz & (data_sz - 1)) || (data_sz % page_sz)) {
		fprintf(stderr, "data_size must be a page-aligned power of two\n");
		return 1;
	}
	mask = data_sz - 1;

	fd = open(DEV_PATH, O_RDWR);
	if (fd < 0) {
		perror(DEV_PATH);
		return 1;
	}

	if (ioctl(fd, XNODE_SHMEM_GET_INFO, &info)) {
		perror("XNODE_SHMEM_GET_INFO");
		return 1;
	}
	if (info.size < 2 * page_sz + data_sz) {
		fprintf(stderr, "window (%llu bytes) smaller than 2 pages + data_size\n",
			(unsigned long long)info.size);
		return 1;
	}

	/* page 0: consumer_pos — the only writable mapping */
	consumer_pos = mmap(NULL, page_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
			    fd, 0);
	if (consumer_pos == MAP_FAILED) {
		perror("mmap consumer_pos");
		return 1;
	}

	/* page 1: producer_pos, read-only */
	producer_pos = mmap(NULL, page_sz, PROT_READ, MAP_SHARED, fd, page_sz);
	if (producer_pos == MAP_FAILED) {
		perror("mmap producer_pos");
		return 1;
	}

	/* pages 2+: data, double-mapped so wrapped records are contiguous */
	reserved = mmap(NULL, 2 * data_sz, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reserved == MAP_FAILED) {
		perror("mmap reserve");
		return 1;
	}
	if (mmap(reserved, data_sz, PROT_READ, MAP_SHARED | MAP_FIXED, fd,
		 2 * page_sz) == MAP_FAILED ||
	    mmap((char *)reserved + data_sz, data_sz, PROT_READ,
		 MAP_SHARED | MAP_FIXED, fd, 2 * page_sz) == MAP_FAILED) {
		perror("mmap data");
		return 1;
	}
	data = reserved;

	for (;;) {
		uint64_t cons = *consumer_pos;
		uint64_t prod = load_acquire64(producer_pos);

		if (cons == prod) {
			/* No doorbell across the fabric in this demo:
			 * poll. A real deployment kicks an eventfd/MSI
			 * through the NIC instead.
			 */
			usleep(1000);
			continue;
		}

		while (cons < prod) {
			const volatile uint32_t *hdr =
				(const volatile uint32_t *)(data + (cons & mask));
			uint32_t len = load_acquire32(hdr);
			uint32_t sample_len;

			if (len & BPF_RINGBUF_BUSY_BIT)
				/* producer still writing this record */
				break;

			sample_len = len & ~BPF_RINGBUF_DISCARD_BIT;
			if (!(len & BPF_RINGBUF_DISCARD_BIT))
				process_sample((const void *)(data +
					       (cons & mask) +
					       BPF_RINGBUF_HDR_SZ),
					       sample_len);

			cons += (sample_len + BPF_RINGBUF_HDR_SZ + 7) & ~7UL;
			/* publish progress so the producer can reuse space */
			store_release64(consumer_pos, cons);
		}
	}

	return 0;
}
