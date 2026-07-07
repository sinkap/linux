// SPDX-License-Identifier: GPL-2.0
/*
 * BPF programs for the multinode dma-buf test: the JIT-inserted arena
 * cache clean, the dma-buf ringbuf producer, and the dma-buf
 * user-ringbuf drain (kernel consumer). The dma-buf maps are created by
 * the userspace test and handed in via bpf_map__reuse_fd().
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define __arena __attribute__((address_space(1)))
#define NUMA_NO_NODE (-1)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4);
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} urb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} result SEC(".maps");

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym;

SEC("syscall")
int arena_writer(void *ctx)
{
	__u64 __arena *p;

	p = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!p)
		return 1;
	*p = 0xABCDULL;
	return 0;
}

SEC("syscall")
int rb_producer(void *ctx)
{
	__u64 *rec = bpf_ringbuf_reserve(&rb, sizeof(*rec), 0);

	if (!rec)
		return 1;
	*rec = 0xF00DULL;
	bpf_ringbuf_submit(rec, 0);
	return 0;
}

static long drain_cb(struct bpf_dynptr *dynptr, void *context)
{
	__u64 v = 0, key = 0, *r;

	bpf_dynptr_read(&v, sizeof(v), dynptr, 0, 0);
	r = bpf_map_lookup_elem(&result, &key);
	if (r)
		*r = v;
	return 0;
}

SEC("syscall")
int urb_drain(void *ctx)
{
	return bpf_user_ringbuf_drain(&urb, drain_cb, NULL, 0);
}

char _license[] SEC("license") = "GPL";
