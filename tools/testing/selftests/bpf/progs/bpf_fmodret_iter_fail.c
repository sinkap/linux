// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("iter/bpf_fmodret")
__failure __msg("invalid mem access")
int dereference_without_null_check(struct bpf_iter__bpf_fmodret *ctx)
{
	return ctx->fmodret_info->btf_id == 0;
}

SEC("iter/bpf_fmodret")
__failure __msg("only read is supported")
int write_fmodret_info(struct bpf_iter__bpf_fmodret *ctx)
{
	struct bpf_fmodret_info *info = ctx->fmodret_info;

	if (info)
		info->flags = 0;
	return 0;
}
