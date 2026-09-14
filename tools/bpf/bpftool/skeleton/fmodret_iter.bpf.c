// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "fmodret_iter.h"

SEC("iter/bpf_fmodret")
int iter(struct bpf_iter__bpf_fmodret *ctx)
{
	struct bpf_fmodret_info *info = ctx->fmodret_info;
	struct fmodret_iter_entry entry;

	if (!info)
		return 0;

	entry.btf_obj_id = info->btf_obj_id;
	entry.btf_id = info->btf_id;
	entry.flags = info->flags;
	bpf_seq_write(ctx->meta->seq, &entry, sizeof(entry));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
