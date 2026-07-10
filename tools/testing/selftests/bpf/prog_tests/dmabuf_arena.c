// SPDX-License-Identifier: GPL-2.0
/*
 * Test BPF_F_DMABUF on BPF_MAP_TYPE_ARENA: an arena whose window is fully
 * pre-populated with a dma-buf's pages (map_extra = dma-buf fd).
 *
 * - the arena, the dma-buf and the dma-buf's source memfd alias the same
 *   pages: a write through one view is visible through the others
 * - a BPF program can bpf_arena_alloc_pages() (pure bookkeeping) and write
 *   through the arena; the store is visible through the dma-buf at the
 *   same offset
 * - invalid map_extra values are rejected
 */
#include <test_progs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/udmabuf.h>
#include "dmabuf_arena_prog.skel.h"

#define ARENA_PAGES	256
#define TEST_MAGIC	0xcafe0001U

static size_t arena_bytes(void)
{
	return (size_t)ARENA_PAGES * getpagesize();
}

/* returns the dma-buf fd, sets *memfdp to the backing memfd */
static int create_udmabuf(int *memfdp)
{
	struct udmabuf_create create;
	int dev_udmabuf, memfd, dmabuf;

	memfd = memfd_create("dmabuf_arena_src", MFD_ALLOW_SEALING);
	if (!ASSERT_OK_FD(memfd, "memfd_create"))
		return -1;
	if (!ASSERT_OK(ftruncate(memfd, arena_bytes()), "ftruncate"))
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
	create.size = arena_bytes();

	dmabuf = ioctl(dev_udmabuf, UDMABUF_CREATE, &create);
	close(dev_udmabuf);
	if (!ASSERT_OK_FD(dmabuf, "udmabuf create"))
		goto close_memfd;

	*memfdp = memfd;
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

	return bpf_map_create(BPF_MAP_TYPE_ARENA, "dmabuf_arena", 0, 0,
			      ARENA_PAGES, &opts);
}

static void subtest_aliasing(int dmabuf, int memfd)
{
	volatile __u32 *p;
	void *mem = MAP_FAILED, *arena = MAP_FAILED, *dbuf = MAP_FAILED;
	int arena_fd;

	arena_fd = create_dmabuf_arena(dmabuf);
	if (!ASSERT_OK_FD(arena_fd, "arena create"))
		return;

	mem = mmap(NULL, arena_bytes(), PROT_READ | PROT_WRITE, MAP_SHARED,
		   memfd, 0);
	arena = mmap(NULL, arena_bytes(), PROT_READ | PROT_WRITE, MAP_SHARED,
		     arena_fd, 0);
	dbuf = mmap(NULL, arena_bytes(), PROT_READ | PROT_WRITE, MAP_SHARED,
		    dmabuf, 0);
	if (!ASSERT_NEQ(mem, MAP_FAILED, "memfd mmap") ||
	    !ASSERT_NEQ(arena, MAP_FAILED, "arena mmap") ||
	    !ASSERT_NEQ(dbuf, MAP_FAILED, "dmabuf mmap"))
		goto out;

	/* write via the memfd, read via the arena */
	p = (volatile __u32 *)((char *)mem + getpagesize());
	*p = TEST_MAGIC;
	ASSERT_EQ(*(volatile __u32 *)((char *)arena + getpagesize()),
		  TEST_MAGIC, "memfd write -> arena read");

	/* write via the arena, read via the dma-buf */
	p = (volatile __u32 *)((char *)arena + 2 * getpagesize());
	*p = TEST_MAGIC + 1;
	ASSERT_EQ(*(volatile __u32 *)((char *)dbuf + 2 * getpagesize()),
		  TEST_MAGIC + 1, "arena write -> dmabuf read");
out:
	if (mem != MAP_FAILED)
		munmap(mem, arena_bytes());
	if (arena != MAP_FAILED)
		munmap(arena, arena_bytes());
	if (dbuf != MAP_FAILED)
		munmap(dbuf, arena_bytes());
	close(arena_fd);
}

static void subtest_bpf_alloc(int dmabuf)
{
	struct dmabuf_arena_prog *skel;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	void *dbuf = MAP_FAILED;
	__u64 off;

	skel = dmabuf_arena_prog__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	bpf_map__set_map_flags(skel->maps.arena, BPF_F_MMAPABLE | BPF_F_DMABUF);
	bpf_map__set_map_extra(skel->maps.arena, dmabuf);
	if (!ASSERT_OK(dmabuf_arena_prog__load(skel), "skel load"))
		goto out;

	skel->bss->magic = TEST_MAGIC + 2;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.alloc_and_write),
					      &topts), "prog run"))
		goto out;
	if (!ASSERT_EQ(topts.retval, 0, "prog retval"))
		goto out;

	off = skel->bss->alloc_off;
	if (!ASSERT_TRUE(off + sizeof(__u32) <= arena_bytes(), "off in range"))
		goto out;

	dbuf = mmap(NULL, arena_bytes(), PROT_READ, MAP_SHARED, dmabuf, 0);
	if (!ASSERT_NEQ(dbuf, MAP_FAILED, "dmabuf mmap"))
		goto out;

	ASSERT_EQ(*(volatile __u32 *)((char *)dbuf + off), TEST_MAGIC + 2,
		  "bpf arena write -> dmabuf read");
out:
	if (dbuf != MAP_FAILED)
		munmap(dbuf, arena_bytes());
	dmabuf_arena_prog__destroy(skel);
}

static void subtest_bad_extra(void)
{
	int fd;

	/* not a dma-buf fd */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_MMAPABLE | BPF_F_DMABUF,
			    .map_extra = 0);
		int memfd = memfd_create("not_dmabuf", 0);

		if (!ASSERT_OK_FD(memfd, "memfd create"))
			return;
		opts.map_extra = memfd;
		fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "bad", 0, 0,
				    ARENA_PAGES, &opts);
		ASSERT_ERR(fd, "non-dmabuf fd rejected");
		close(memfd);
	}

	/* map_extra must fit in an fd */
	{
		LIBBPF_OPTS(bpf_map_create_opts, opts,
			    .map_flags = BPF_F_MMAPABLE | BPF_F_DMABUF,
			    .map_extra = 1ULL << 32);

		fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "bad2", 0, 0,
				    ARENA_PAGES, &opts);
		ASSERT_EQ(fd, -EINVAL, "oversized map_extra rejected");
	}
}

void test_dmabuf_arena(void)
{
	int memfd = -1, dmabuf;

	dmabuf = create_udmabuf(&memfd);
	if (dmabuf < 0)
		return;

	if (test__start_subtest("aliasing"))
		subtest_aliasing(dmabuf, memfd);
	if (test__start_subtest("bpf_alloc"))
		subtest_bpf_alloc(dmabuf);
	if (test__start_subtest("bad_extra"))
		subtest_bad_extra();

	close(dmabuf);
	close(memfd);
}
