#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"

#define MAX_CPUS 128
#define ENV_BUFFER_MAX 4096

struct bpf_map_def SEC("maps") env_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = ENV_BUFFER_MAX,
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPUS,
};

SEC("krsi")
int bpf_prog1(void *ctx)
{
	u32 map_id = 0;
	char *map_value = bpf_map_lookup_elem(&env_map, &map_id);
	if (!map_value)
		return 0;

	int len = krsi_get_bprm_envs(ctx, map_value, ENV_BUFFER_MAX);
	if (len < 0)
		return len;
	if (len > ENV_BUFFER_MAX)
		return 0;

	bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU,
			       map_value, len);
	return 0;
}
char _license[] SEC("license") = "GPL";
