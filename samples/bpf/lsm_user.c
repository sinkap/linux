// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/resource.h>

#include "perf-sys.h"
#include "trace_helpers.h"

#define LSM_HOOK_PATH "/sys/kernel/security/krsi/bprm_check_security"
#define MAX_CPUS 128

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];

static int print_env(void *d, int size)
{
	const char *data = d;
	int offset = 0;
	while(offset < size) {
		printf("%s\n", data + offset);
		offset += strlen(data + offset) + 1;
	}
	return LIBBPF_PERF_EVENT_CONT;
}


static int open_perf_events(int map_fd, int num)
{
	int i;
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.wakeup_events = 1, /* get an fd notification for every event */
	};

	for (i = 0; i < num; i++) {
		int key = i;
		int ret;

		ret = sys_perf_event_open(&attr, -1 /*pid*/, i/*cpu*/,
					 -1/*group_fd*/, 0);
		if (ret < 0)
			return ret;
		pmu_fds[i] = ret;
		ret = bpf_map_update_elem(map_fd, &key, &pmu_fds[i], BPF_ANY);
		if (ret < 0)
			return ret;
		ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
	}
	return 0;
}

int main(int ac, char **argv)
{
	struct bpf_object *prog_obj;
	struct bpf_prog_load_attr attr;
	int prog_fd, target_fd, map_fd;
	int ret, i, numcpus;
	struct bpf_map *map;
	char filename[256];

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
	attr.prog_type = BPF_PROG_TYPE_KRSI;
	attr.expected_attach_type = KRSI;
	attr.file = filename;

	/* Attach the BPF program to the given hook */
	target_fd = open(LSM_HOOK_PATH, O_RDONLY);
	if (target_fd < 0) {
		printf("Failed to open target: '%s'\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	if (bpf_prog_load_xattr(&attr, &prog_obj, &prog_fd))
		return EXIT_FAILURE;

	numcpus = get_nprocs();
	if (numcpus > MAX_CPUS)
		numcpus = MAX_CPUS;

	map = bpf_object__find_map_by_name(prog_obj, "perf_map");
	if (!map) {
		printf("Finding the perf event map in obj file failed\n");
		return EXIT_FAILURE;
	}
	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		printf("Failed to get fd for perf events map '%s'\n",
		       strerror(map_fd));
		return EXIT_FAILURE;
	}

	ret = bpf_prog_attach(prog_fd, target_fd, KRSI, 0);
	if (ret < 0) {
		printf("Failed to attach prog to LSM hook '%s'\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	ret = open_perf_events(map_fd, numcpus);
	if (ret < 0) {
		printf("Failed to open perf events '%s'\n", strerror(ret));
		return EXIT_FAILURE;
	}

	for (i = 0; i < numcpus; i++) {
		ret = perf_event_mmap_header(pmu_fds[i], &headers[i]);
		if (ret < 0) {
			printf("perf_event_mmap_header '%s'\n", strerror(ret));
			return EXIT_FAILURE;
		}
	}

	ret = perf_event_poller_multi(pmu_fds, headers, numcpus,
				      print_env);
	if (ret < 0) {
		printf("Failed to poll perf events '%s'\n", strerror(ret));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
