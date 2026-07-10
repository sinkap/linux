// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

char _license[] SEC("license") = "GPL";

/* The test adds BPF_F_DMABUF and sets map_extra to a dma-buf fd before
 * load; max_entries must match the dma-buf size (256 pages).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 256);
} arena SEC(".maps");

__u64 alloc_off;	/* offset of the allocated page within the arena */
__u32 magic;		/* value to store, set by the test */

SEC("syscall")
int alloc_and_write(void *ctx)
{
	__u32 __arena *p;

	/* pure range-tree bookkeeping for a dma-buf backed arena: the whole
	 * window is pre-populated with the dma-buf's pages
	 */
	p = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!p)
		return 1;
	*p = magic;
	/* lower 32 bits of the user pointer are the offset in the window */
	alloc_off = (__u32)(long)p;
	return 0;
}
