// SPDX-License-Identifier: GPL-2.0
/*
 * Composition test: a ring buffer backed by a dma-buf backed arena.
 *
 *   dma-buf (udmabuf) -> arena (BPF_F_DMABUF, map_extra = dma-buf fd)
 *                     -> ring buffer (BPF_F_ARENA_BACKED, map_extra = arena fd)
 *
 * A BPF program produces a record through the normal ring buffer API; the
 * consumer reads it back through the DMA-BUF ALONE at the offset reported
 * in bpf_map_info.arena_off — exactly how a peer that only shares the
 * dma-buf consumes such a ring buffer.
 */
#include <test_progs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/udmabuf.h>
#include "ringbuf_arena_backed.skel.h"

#define ARENA_PAGES	256
#define RB_SIZE		(64 * 1024)
#define TEST_PAYLOAD	0x5ec00001U

#define RB_BUSY_BIT	(1U << 31)
#define RB_DISCARD_BIT	(1U << 30)
#define RB_POS_PAGES	2

static size_t win_bytes(void)
{
	return (size_t)ARENA_PAGES * getpagesize();
}

static int create_udmabuf(void)
{
	struct udmabuf_create create;
	int dev_udmabuf, memfd, dmabuf;

	memfd = memfd_create("rb_dmabuf_arena_src", MFD_ALLOW_SEALING);
	if (!ASSERT_OK_FD(memfd, "memfd_create"))
		return -1;
	if (!ASSERT_OK(ftruncate(memfd, win_bytes()), "ftruncate"))
		goto close_memfd;
	if (!ASSERT_OK(fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK), "seal"))
		goto close_memfd;

	dev_udmabuf = open("/dev/udmabuf", O_RDONLY);
	if (dev_udmabuf < 0) {
		test__skip();	/* no udmabuf support */
		goto close_memfd;
	}

	memset(&create, 0, sizeof(create));
	create.memfd = memfd;
	create.flags = UDMABUF_FLAGS_CLOEXEC;
	create.offset = 0;
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

void test_ringbuf_dmabuf_arena(void)
{
	struct ringbuf_arena_backed *skel = NULL;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_map_info info = {}, ainfo = {};
	__u32 len = sizeof(info);
	int dmabuf = -1, arena_fd = -1, rb_fd = -1;
	int page_size = getpagesize();
	unsigned char *dbuf = MAP_FAILED, *data;
	unsigned long prod_pos;
	__u32 hdr_len;

	dmabuf = create_udmabuf();
	if (dmabuf < 0)
		return;

	/* arena on the dma-buf */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_MMAPABLE | BPF_F_DMABUF,
			    .map_extra = dmabuf);

		arena_fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "win_arena",
					  0, 0, ARENA_PAGES, &opts);
	}
	if (!ASSERT_OK_FD(arena_fd, "arena create"))
		goto out;

	/* ring buffer inside the arena */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_ARENA_BACKED,
			    .map_extra = arena_fd);

		rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb_in_win",
				       0, 0, RB_SIZE, &opts);
	}
	if (!ASSERT_OK_FD(rb_fd, "ringbuf create"))
		goto out;

	/* discover the kernel-chosen placement */
	if (!ASSERT_OK(bpf_map_get_info_by_fd(rb_fd, &info, &len), "rb info"))
		goto out;
	len = sizeof(ainfo);
	if (!ASSERT_OK(bpf_map_get_info_by_fd(arena_fd, &ainfo, &len), "arena info"))
		goto out;
	ASSERT_EQ(info.arena_id, ainfo.id, "arena_id");
	if (!ASSERT_TRUE(info.arena_off + RB_POS_PAGES * page_size + RB_SIZE <=
			 win_bytes(), "arena_off in range"))
		goto out;

	/* produce through the normal ring buffer API */
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

	/* consume as a peer would: through the dma-buf only */
	dbuf = mmap(NULL, win_bytes(), PROT_READ, MAP_SHARED, dmabuf, 0);
	if (!ASSERT_NEQ(dbuf, MAP_FAILED, "dmabuf mmap"))
		goto out;

	prod_pos = *(volatile unsigned long *)(dbuf + info.arena_off + page_size);
	ASSERT_EQ(prod_pos, 16, "producer_pos via dmabuf");

	data = dbuf + info.arena_off + RB_POS_PAGES * page_size;
	hdr_len = *(volatile __u32 *)data & ~(RB_BUSY_BIT | RB_DISCARD_BIT);
	ASSERT_EQ(hdr_len, sizeof(__u32), "record len via dmabuf");
	ASSERT_EQ(*(volatile __u32 *)(data + 8), TEST_PAYLOAD,
		  "record payload via dmabuf");
out:
	if (dbuf != MAP_FAILED)
		munmap(dbuf, win_bytes());
	ringbuf_arena_backed__destroy(skel);
	if (rb_fd >= 0)
		close(rb_fd);
	if (arena_fd >= 0)
		close(arena_fd);
	if (dmabuf >= 0)
		close(dmabuf);
}
