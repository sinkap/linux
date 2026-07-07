/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MULTINODE_COMMON_H
#define _MULTINODE_COMMON_H

#include <cstdint>

/*
 * Shared layout for the dma-buf backed ringbuf, as produced by the
 * kernel and consumed here (see Documentation/bpf/multi-node-bpf.md):
 *
 *   dma-buf page 0:  consumer_pos
 *   dma-buf page 1:  producer_pos
 *   dma-buf page 2+: data
 */
static const uint32_t BUSY_BIT = 1u << 31;
static const uint32_t DISCARD_BIT = 1u << 30;
static const uint32_t HDR_SZ = 8;

/* Record payload the producer BPF program writes: an 8-byte sequence. */
struct record {
	uint64_t seq;
};

static inline uint64_t round_up8(uint64_t x)
{
	return (x + 7) & ~7ull;
}

#endif /* _MULTINODE_COMMON_H */
