// SPDX-License-Identifier: GPL-2.0
/*
 * Test BPF_F_ARENA_BACKED: a map whose backing pages come from a
 * kernel-chosen sub-region of an arena instead of pages it allocates
 * itself. bpf_map_info reports the placement (arena_id, arena_off) so a
 * peer that maps the same arena/dma-buf can find the data.
 *
 * ringbuf: consumer/producer position pages + data pages live in the arena;
 *   produce through the normal ring buffer API, read back through the arena.
 * array:  the value region lives in the arena; mmap()ing the array fd reads
 *   value[0] at offset 0 (the kernel hides the arena offset), while a peer
 *   reads the same bytes through the arena at arena_off + elem_size*index.
 *
 * The dmabuf_* subtests repeat this with the arena backed by a dma-buf
 * (BPF_F_DMABUF, a udmabuf here) and consume purely through the dma-buf at
 * arena_off — the shape a peer node that only shares the dma-buf sees.
 */
#include <test_progs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/udmabuf.h>
#include "arena_backed_maps.skel.h"

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

static int create_arena_backed_array(int arena_fd, __u32 value_size,
				     __u32 max_entries, bool mmapable)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_ARENA_BACKED |
				 (mmapable ? BPF_F_MMAPABLE : 0),
		    .map_extra = arena_fd);

	return bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr_arena", 4, value_size,
			      max_entries, &opts);
}

static void subtest_placement_and_data(void)
{
	struct arena_backed_maps *skel = NULL;
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

	skel = arena_backed_maps__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel->maps.ringbuf, rb_fd), "reuse fd"))
		goto out;
	if (!ASSERT_OK(arena_backed_maps__load(skel), "skel load"))
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
	arena_backed_maps__destroy(skel);
	if (rb_fd >= 0)
		close(rb_fd);
	if (arena_fd >= 0)
		close(arena_fd);
}

static void subtest_array(void)
{
	struct bpf_map_info info = {}, ainfo = {};
	const __u32 nr = 64, vsz = sizeof(__u64);
	int arena_fd = -1, arr_fd = -1, page_size = getpagesize();
	__u64 *arena_vals, *fd_vals;
	void *arena = MAP_FAILED, *vals = MAP_FAILED;
	__u32 len = sizeof(info), key;
	__u64 v;
	int i;

	arena_fd = create_arena();
	if (!ASSERT_OK_FD(arena_fd, "arena create"))
		return;

	arr_fd = create_arena_backed_array(arena_fd, vsz, nr, true);
	if (!ASSERT_OK_FD(arr_fd, "array create"))
		goto out;

	if (!ASSERT_OK(bpf_map_get_info_by_fd(arr_fd, &info, &len), "array info"))
		goto out;
	len = sizeof(ainfo);
	if (!ASSERT_OK(bpf_map_get_info_by_fd(arena_fd, &ainfo, &len), "arena info"))
		goto out;
	ASSERT_EQ(info.arena_id, ainfo.id, "arena_id");
	ASSERT_TRUE(info.arena_off + (__u64)nr * vsz <=
		    (__u64)ARENA_PAGES * page_size, "arena_off in range");

	/* Local view: mmap the array fd. value[i] is at offset i*vsz, from 0 —
	 * the arena offset is invisible here.
	 */
	vals = mmap(NULL, (size_t)nr * vsz, PROT_READ | PROT_WRITE, MAP_SHARED,
		    arr_fd, 0);
	if (!ASSERT_NEQ(vals, MAP_FAILED, "mmap array fd"))
		goto out;
	/* Peer view: the whole arena; value[i] at arena_off + i*vsz. */
	arena = mmap((void *)ARENA_ADDR, (size_t)ARENA_PAGES * page_size,
		     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, arena_fd, 0);
	if (!ASSERT_NEQ(arena, MAP_FAILED, "mmap arena"))
		goto out;

	fd_vals = vals;
	arena_vals = (void *)((char *)arena + info.arena_off);

	/* write through the array fd (from 0), read through the arena */
	for (i = 0; i < nr; i++)
		fd_vals[i] = 0x1000 + i;
	for (i = 0; i < nr; i++)
		if (!ASSERT_EQ(arena_vals[i], 0x1000 + i,
			       "array-fd write visible in arena"))
			break;

	/* write through the arena, read through the array fd and the map API */
	for (i = 0; i < nr; i++)
		arena_vals[i] = 0x2000 + i;
	for (i = 0; i < nr; i++)
		if (!ASSERT_EQ(fd_vals[i], 0x2000 + i,
			       "arena write visible via array fd"))
			break;
	key = 5;
	if (ASSERT_OK(bpf_map_lookup_elem(arr_fd, &key, &v), "map lookup"))
		ASSERT_EQ(v, 0x2000 + 5, "map lookup matches arena");
out:
	if (vals != MAP_FAILED)
		munmap(vals, (size_t)nr * vsz);
	if (arena != MAP_FAILED)
		munmap(arena, (size_t)ARENA_PAGES * page_size);
	if (arr_fd >= 0)
		close(arr_fd);
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

	/* an arena-backed array cannot also be an inner map */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_ARENA_BACKED | BPF_F_INNER_MAP,
			    .map_extra = arena_fd);

		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr_inner", 4, 8,
				    16, &opts);
		ASSERT_EQ(fd, -EINVAL, "array + inner_map rejected");
	}

	/* an array too large for the arena cannot be placed */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_ARENA_BACKED,
			    .map_extra = arena_fd);

		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr_big", 4, 8,
				    2 * ARENA_PAGES * getpagesize() / 8, &opts);
		ASSERT_EQ(fd, -ENOMEM, "oversized array rejected");
	}

	close(arena_fd);
}

/* ---- the same maps in a dma-buf backed arena, consumed via the dma-buf ---- */

static size_t win_bytes(void)
{
	return (size_t)ARENA_PAGES * getpagesize();
}

/* returns a dma-buf fd (from a udmabuf), or -1; skips if no /dev/udmabuf */
static int create_udmabuf(void)
{
	struct udmabuf_create create;
	int dev_udmabuf, memfd, dmabuf;

	memfd = memfd_create("arena_backed_win", MFD_ALLOW_SEALING);
	if (!ASSERT_OK_FD(memfd, "memfd_create"))
		return -1;
	if (!ASSERT_OK(ftruncate(memfd, win_bytes()), "ftruncate") ||
	    !ASSERT_OK(fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK), "seal"))
		goto close_memfd;

	dev_udmabuf = open("/dev/udmabuf", O_RDONLY);
	if (dev_udmabuf < 0) {
		test__skip();
		goto close_memfd;
	}
	memset(&create, 0, sizeof(create));
	create.memfd = memfd;
	create.flags = UDMABUF_FLAGS_CLOEXEC;
	create.size = win_bytes();
	dmabuf = ioctl(dev_udmabuf, UDMABUF_CREATE, &create);
	close(dev_udmabuf);
	close(memfd);
	if (!ASSERT_OK_FD(dmabuf, "udmabuf create"))
		return -1;
	return dmabuf;

close_memfd:
	close(memfd);
	return -1;
}

static int create_dmabuf_arena(int dmabuf)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		    .map_flags = BPF_F_MMAPABLE | BPF_F_DMABUF,
		    .map_extra = dmabuf);

	return bpf_map_create(BPF_MAP_TYPE_ARENA, "win_arena", 0, 0,
			      ARENA_PAGES, &opts);
}

static void subtest_ringbuf_dmabuf(void)
{
	struct arena_backed_maps *skel = NULL;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_map_info info = {}, ainfo = {};
	__u32 len = sizeof(info);
	int dmabuf = -1, arena_fd = -1, rb_fd = -1, page_size = getpagesize();
	unsigned char *dbuf = MAP_FAILED, *data;
	unsigned long prod_pos;

	dmabuf = create_udmabuf();
	if (dmabuf < 0)
		return;

	arena_fd = create_dmabuf_arena(dmabuf);
	if (!ASSERT_OK_FD(arena_fd, "dmabuf arena create"))
		goto out;
	rb_fd = create_arena_backed_rb(arena_fd);
	if (!ASSERT_OK_FD(rb_fd, "ringbuf create"))
		goto out;

	if (!ASSERT_OK(bpf_map_get_info_by_fd(rb_fd, &info, &len), "rb info"))
		goto out;
	len = sizeof(ainfo);
	ASSERT_OK(bpf_map_get_info_by_fd(arena_fd, &ainfo, &len), "arena info");
	ASSERT_EQ(info.arena_id, ainfo.id, "arena_id");

	skel = arena_backed_maps__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel->maps.ringbuf, rb_fd), "reuse fd") ||
	    !ASSERT_OK(arena_backed_maps__load(skel), "skel load"))
		goto out;
	skel->bss->payload = TEST_PAYLOAD;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.produce),
					      &topts), "produce") ||
	    !ASSERT_EQ(topts.retval, 0, "produce retval"))
		goto out;

	/* consume as a peer would: through the dma-buf only, at arena_off */
	dbuf = mmap(NULL, win_bytes(), PROT_READ, MAP_SHARED, dmabuf, 0);
	if (!ASSERT_NEQ(dbuf, MAP_FAILED, "mmap dmabuf"))
		goto out;
	prod_pos = *(volatile unsigned long *)(dbuf + info.arena_off + page_size);
	ASSERT_EQ(prod_pos, 16, "producer_pos via dmabuf");
	data = dbuf + info.arena_off + RB_POS_PAGES * page_size;
	ASSERT_EQ(*(volatile __u32 *)data & ~(RB_BUSY_BIT | RB_DISCARD_BIT),
		  sizeof(__u32), "record len via dmabuf");
	ASSERT_EQ(*(volatile __u32 *)(data + 8), TEST_PAYLOAD,
		  "record payload via dmabuf");
out:
	if (dbuf != MAP_FAILED)
		munmap(dbuf, win_bytes());
	arena_backed_maps__destroy(skel);
	if (rb_fd >= 0)
		close(rb_fd);
	if (arena_fd >= 0)
		close(arena_fd);
	if (dmabuf >= 0)
		close(dmabuf);
}

static void subtest_array_dmabuf(void)
{
	struct bpf_map_info info = {};
	const __u32 nr = 64, vsz = sizeof(__u64);
	int dmabuf = -1, arena_fd = -1, arr_fd = -1;
	void *vals = MAP_FAILED, *dbuf = MAP_FAILED;
	__u64 *fd_vals, *peer_vals;
	__u32 len = sizeof(info);
	int i;

	dmabuf = create_udmabuf();
	if (dmabuf < 0)
		return;

	arena_fd = create_dmabuf_arena(dmabuf);
	if (!ASSERT_OK_FD(arena_fd, "dmabuf arena create"))
		goto out;
	arr_fd = create_arena_backed_array(arena_fd, vsz, nr, true);
	if (!ASSERT_OK_FD(arr_fd, "array create"))
		goto out;
	if (!ASSERT_OK(bpf_map_get_info_by_fd(arr_fd, &info, &len), "array info"))
		goto out;

	vals = mmap(NULL, (size_t)nr * vsz, PROT_READ | PROT_WRITE, MAP_SHARED,
		    arr_fd, 0);
	dbuf = mmap(NULL, win_bytes(), PROT_READ, MAP_SHARED, dmabuf, 0);
	if (!ASSERT_NEQ(vals, MAP_FAILED, "mmap array fd") ||
	    !ASSERT_NEQ(dbuf, MAP_FAILED, "mmap dmabuf"))
		goto out;

	fd_vals = vals;
	peer_vals = (void *)((char *)dbuf + info.arena_off);
	/* write through the array fd (from 0); the peer reads it in the dma-buf */
	for (i = 0; i < nr; i++)
		fd_vals[i] = 0xa000 + i;
	for (i = 0; i < nr; i++)
		if (!ASSERT_EQ(peer_vals[i], 0xa000 + i,
			       "array value visible in dmabuf at arena_off"))
			break;
out:
	if (vals != MAP_FAILED)
		munmap(vals, (size_t)nr * vsz);
	if (dbuf != MAP_FAILED)
		munmap(dbuf, win_bytes());
	if (arr_fd >= 0)
		close(arr_fd);
	if (arena_fd >= 0)
		close(arena_fd);
	if (dmabuf >= 0)
		close(dmabuf);
}

void test_arena_backed_maps(void)
{
	if (test__start_subtest("ringbuf"))
		subtest_placement_and_data();
	if (test__start_subtest("array"))
		subtest_array();
	if (test__start_subtest("bad_flags"))
		subtest_bad_flags();
	if (test__start_subtest("ringbuf_dmabuf"))
		subtest_ringbuf_dmabuf();
	if (test__start_subtest("array_dmabuf"))
		subtest_array_dmabuf();
}
