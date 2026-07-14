// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

long produced = 0;

SEC("syscall")
int produce(void *ctx)
{
	__u64 *v;

	v = bpf_ringbuf_reserve(&ringbuf, sizeof(*v), 0);
	if (!v)
		return 1;
	*v = produced;
	/* force a wakeup per record: the eventfd/doorbell must fire even
	 * with no consumer position to compare against
	 */
	bpf_ringbuf_submit(v, BPF_RB_FORCE_WAKEUP);
	produced++;
	return 0;
}
