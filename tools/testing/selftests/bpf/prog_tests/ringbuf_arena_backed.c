// SPDX-License-Identifier: GPL-2.0
/*
 * Test BPF_F_ARENA_BACKED: a ring buffer whose consumer/producer position
 * pages and data pages live in a kernel-chosen sub-region of an arena.
 *
 * - create a plain arena at a fixed user address
 * - create a ring buffer backed by it (map_extra = arena fd)
 * - check bpf_map_info reports the arena id and the chosen byte offset
 * - produce one record through the normal ring buffer API
 * - read the record back through the arena mapping at arena_off
 * - check invalid combinations are rejected
 */
#include <test_progs.h>
#include <sys/mman.h>
#include "ringbuf_arena_backed.skel.h"

#define ARENA_ADDR	0x100000000000ULL	/* fixed, 4G-aligned */
#define ARENA_PAGES	1024
#define RB_SIZE		(64 * 1024)
#define TEST_PAYLOAD	0x1234abcdU

#define RB_BUSY_BIT	(1U << 31)
#define RB_DISCARD_BIT	(1U << 30)
/* consumer_pos page + producer_pos page precede the data pages */
#define RB_POS_PAGES	2

static int create_arena(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_MMAPABLE,
		    .map_extra = ARENA_ADDR);

	return bpf_map_create(BPF_MAP_TYPE_ARENA, "arena", 0, 0,
			      ARENA_PAGES, &opts);
}

static int create_arena_backed_rb(int arena_fd)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_ARENA_BACKED,
		    .map_extra = arena_fd);

	return bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb_arena", 0, 0,
			      RB_SIZE, &opts);
}

static void subtest_placement_and_data(void)
{
	struct ringbuf_arena_backed *skel = NULL;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_map_info info = {}, ainfo = {};
	__u32 len = sizeof(info);
	int arena_fd = -1, rb_fd = -1, page_size = getpagesize();
	volatile __u32 *rec;
	unsigned long *prod_pos;
	void *base = MAP_FAILED;
	__u32 hdr_len;

	arena_fd = create_arena();
	if (!ASSERT_OK_FD(arena_fd, "arena create"))
		return;

	rb_fd = create_arena_backed_rb(arena_fd);
	if (!ASSERT_OK_FD(rb_fd, "ringbuf create"))
		goto out;

	if (!ASSERT_OK(bpf_map_get_info_by_fd(rb_fd, &info, &len), "rb info"))
		goto out;
	len = sizeof(ainfo);
	if (!ASSERT_OK(bpf_map_get_info_by_fd(arena_fd, &ainfo, &len), "arena info"))
		goto out;

	ASSERT_EQ(info.arena_id, ainfo.id, "arena_id");
	ASSERT_TRUE(info.arena_off + RB_POS_PAGES * page_size + RB_SIZE <=
		    (unsigned long long)ARENA_PAGES * page_size, "arena_off in range");

	skel = ringbuf_arena_backed__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel->maps.ringbuf, rb_fd), "reuse fd"))
		goto out;
	if (!ASSERT_OK(ringbuf_arena_backed__load(skel), "skel load"))
		goto out;
	skel->bss->payload = TEST_PAYLOAD;

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.produce),
					      &topts), "produce run"))
		goto out;
	if (!ASSERT_EQ(topts.retval, 0, "produce retval"))
		goto out;

	/* the consumer view: the arena mapping at the reported offset */
	base = mmap((void *)ARENA_ADDR, (size_t)ARENA_PAGES * page_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, arena_fd, 0);
	if (!ASSERT_NEQ(base, MAP_FAILED, "arena mmap"))
		goto out;

	prod_pos = (unsigned long *)((char *)base + info.arena_off + page_size);
	ASSERT_EQ(*prod_pos, 16, "producer_pos");

	rec = (volatile __u32 *)((char *)base + info.arena_off +
				 RB_POS_PAGES * page_size);
	hdr_len = rec[0] & ~(RB_BUSY_BIT | RB_DISCARD_BIT);
	ASSERT_EQ(hdr_len, sizeof(__u32), "record len");
	ASSERT_EQ(rec[2], TEST_PAYLOAD, "record payload");
out:
	if (base != MAP_FAILED)
		munmap(base, (size_t)ARENA_PAGES * getpagesize());
	ringbuf_arena_backed__destroy(skel);
	if (rb_fd >= 0)
		close(rb_fd);
	if (arena_fd >= 0)
		close(arena_fd);
}

static void subtest_bad_flags(void)
{
	int arena_fd, fd;

	arena_fd = create_arena();
	if (!ASSERT_OK_FD(arena_fd, "arena create"))
		return;

	/* overwrite mode keeps state in the shared producer page: rejected */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_ARENA_BACKED | BPF_F_RB_OVERWRITE,
			    .map_extra = arena_fd);

		fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb_ovw", 0, 0,
				    RB_SIZE, &opts);
		ASSERT_EQ(fd, -EINVAL, "overwrite rejected");
	}

	/* map_extra must be an arena fd */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_ARENA_BACKED,
			    .map_extra = arena_fd);
		int not_arena = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr", 4, 4,
					       1, NULL);

		if (ASSERT_OK_FD(not_arena, "array create")) {
			opts.map_extra = not_arena;
			fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb_arr", 0, 0,
					    RB_SIZE, &opts);
			ASSERT_EQ(fd, -EINVAL, "non-arena fd rejected");
			close(not_arena);
		}
	}

	/* a ring buffer larger than the arena cannot be placed */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_ARENA_BACKED,
			    .map_extra = arena_fd);

		fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb_big", 0, 0,
				    2 * ARENA_PAGES * getpagesize(), &opts);
		ASSERT_EQ(fd, -ENOMEM, "oversized rejected");
	}

	close(arena_fd);
}

void test_ringbuf_arena_backed(void)
{
	if (test__start_subtest("placement_and_data"))
		subtest_placement_and_data();
	if (test__start_subtest("bad_flags"))
		subtest_bad_flags();
}
