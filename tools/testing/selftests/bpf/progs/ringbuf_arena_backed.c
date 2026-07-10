// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* The fd of this map is replaced (bpf_map__reuse_fd) with an arena-backed
 * ring buffer created by the test; max_entries is only a placeholder.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

__u32 payload;

SEC("syscall")
int produce(void *ctx)
{
	__u32 *rec = bpf_ringbuf_reserve(&ringbuf, sizeof(*rec), 0);

	if (!rec)
		return 1;
	*rec = payload;
	bpf_ringbuf_submit(rec, 0);
	return 0;
}
