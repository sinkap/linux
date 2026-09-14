// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_fmodret_iter.h"

__u32 num_entries;
__u32 num_terminal;

SEC("iter/bpf_fmodret")
int dump_bpf_fmodret(struct bpf_iter__bpf_fmodret *ctx)
{
	struct bpf_fmodret_info *info = ctx->fmodret_info;
	struct bpf_fmodret_iter_entry entry;

	if (!info) {
		num_terminal++;
		return 0;
	}

	entry.btf_obj_id = info->btf_obj_id;
	entry.btf_id = info->btf_id;
	entry.flags = info->flags;
	num_entries++;

	bpf_seq_write(ctx->meta->seq, &entry, sizeof(entry));
	return 0;
}

char _license[] SEC("license") = "GPL";
