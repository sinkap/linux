// SPDX-License-Identifier: GPL-2.0
/*
 * Runtime coverage for the dma-buf backed BPF maps used by the
 * multi-node work: the JIT-inserted arena cache clean, the ringbuf
 * producer (kernel cleans on submit) and the user-ringbuf drain (kernel
 * consumer invalidates on consume).
 *
 * libbpf does not create dma-buf maps (map_extra is a dma-buf fd, not a
 * user VM start), so each is created here and handed to the loaded
 * program with bpf_map__reuse_fd().
 *
 * A single QEMU/coherent guest cannot show the non-coherency benefit;
 * these checks confirm the code paths are reached and correct.
 */
#include <test_progs.h>
#include <sys/mman.h>
#include <linux/dma-heap.h>
#include "multinode_dmabuf.skel.h"

#ifndef BPF_F_DMABUF
#define BPF_F_DMABUF		(1U << 20)
#endif
#ifndef BPF_F_ARENA_CLEAN
#define BPF_F_ARENA_CLEAN	(1U << 21)
#endif

#define HDR_SZ 8u

static int dmabuf_alloc(unsigned long npages)
{
	long page = sysconf(_SC_PAGESIZE);
	int heap = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);

	if (heap < 0)
		return -1;
	struct dma_heap_allocation_data a = { .len = (__u64)npages * page,
					      .fd_flags = O_RDWR | O_CLOEXEC };
	int ret = ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a);

	close(heap);
	return ret ? -1 : (int)a.fd;
}

static int reuse_dmabuf(struct bpf_map *m, enum bpf_map_type type,
			__u32 max_entries, __u32 extra_flags,
			unsigned long npages, int *dmabuf_out)
{
	int dmabuf = dmabuf_alloc(npages);

	if (dmabuf < 0)
		return -1;
	LIBBPF_OPTS(bpf_map_create_opts, o,
		    .map_flags = BPF_F_DMABUF | extra_flags,
		    .map_extra = (__u32)dmabuf);
	int fd = bpf_map_create(type, bpf_map__name(m), 0, 0, max_entries, &o);

	if (fd < 0 || bpf_map__reuse_fd(m, fd)) {
		close(fd);
		close(dmabuf);
		return -1;
	}
	*dmabuf_out = dmabuf;
	return fd;
}

static int run(struct bpf_program *p)
{
	unsigned char ctx[8] = {};
	LIBBPF_OPTS(bpf_test_run_opts, t, .ctx_in = ctx, .ctx_size_in = sizeof(ctx));

	if (bpf_prog_test_run_opts(bpf_program__fd(p), &t))
		return -1;
	return (int)t.retval;
}

void test_multinode_dmabuf(void)
{
	long page = sysconf(_SC_PAGESIZE);
	int arena_db = -1, rb_db = -1, urb_db = -1;
	struct multinode_dmabuf *skel;
	int rb_fd, urb_fd, heap;

	/* Needs a system dma-buf heap to allocate the shared backing. */
	heap = open("/dev/dma_heap/system", O_RDONLY | O_CLOEXEC);
	if (heap < 0) {
		test__skip();
		return;
	}
	close(heap);

	skel = multinode_dmabuf__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	/* The arena create doubles as a feature probe: a kernel without
	 * BPF_F_DMABUF, or an arch whose JIT can't emit the arena cache
	 * maintenance, rejects it. Skip rather than fail in that case.
	 */
	if (reuse_dmabuf(skel->maps.arena, BPF_MAP_TYPE_ARENA, 4,
			 BPF_F_MMAPABLE | BPF_F_ARENA_CLEAN, 4, &arena_db) < 0) {
		test__skip();
		goto cleanup;
	}
	/* Support is established; from here a failure is a real regression. */
	rb_fd = reuse_dmabuf(skel->maps.rb, BPF_MAP_TYPE_RINGBUF, 4096,
			     0, 3, &rb_db);
	urb_fd = reuse_dmabuf(skel->maps.urb, BPF_MAP_TYPE_USER_RINGBUF,
			      4096, 0, 3, &urb_db);
	if (!ASSERT_GE(rb_fd, 0, "ringbuf dma-buf map") ||
	    !ASSERT_GE(urb_fd, 0, "user-ringbuf dma-buf map"))
		goto cleanup;

	/* arena needs user_vm_start set before a program references it */
	mmap((void *)0x4000000000ULL, 4 * page, PROT_READ | PROT_WRITE,
	     MAP_SHARED | MAP_FIXED, arena_db >= 0 ?
	     bpf_map__fd(skel->maps.arena) : -1, 0);

	if (!ASSERT_OK(multinode_dmabuf__load(skel), "skel load"))
		goto cleanup;

	/* arena: the JIT must emit a cache clean after the arena store */
	if (test__start_subtest("arena_jit_clean")) {
		static unsigned char jit[65536];
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		bool maint = false;
		int fd = bpf_program__fd(skel->progs.arena_writer);

		info.jited_prog_insns = ptr_to_u64(jit);
		info.jited_prog_len = sizeof(jit);
		if (ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &len), "jit info")) {
			__u32 n = info.jited_prog_len < sizeof(jit) ?
				  info.jited_prog_len : sizeof(jit);
#if defined(__x86_64__)
			/* clflush is 0F AE /7 with a memory operand
			 * (ModRM.mod != 3); the mod check excludes sfence
			 * (0F AE F8), which also has reg == 7.
			 */
			for (__u32 i = 0; i + 2 < n; i++)
				if (jit[i] == 0x0f && jit[i + 1] == 0xae &&
				    ((jit[i + 2] >> 3) & 7) == 7 &&
				    ((jit[i + 2] >> 6) != 3)) {
					maint = true;
					break;
				}
#elif defined(__aarch64__)
			/* dc cvac (0xd50b7a20) / dc ivac (0xd5087620), with
			 * the Xt register in the low 5 bits.
			 */
			for (__u32 i = 0; i + 3 < n; i += 4) {
				__u32 w = jit[i] | jit[i + 1] << 8 |
					  jit[i + 2] << 16 |
					  (__u32)jit[i + 3] << 24;

				if ((w & ~0x1fU) == 0xd50b7a20U ||
				    (w & ~0x1fU) == 0xd5087620U) {
					maint = true;
					break;
				}
			}
#else
			test__skip();
			maint = true; /* don't fail on unknown arch */
#endif
		}
		ASSERT_TRUE(maint, "cache maintenance emitted after arena store");
		ASSERT_EQ(run(skel->progs.arena_writer), 0, "arena_writer runs");
	}

	/* ringbuf producer: record is readable from the dma-buf */
	if (test__start_subtest("ringbuf_producer")) {
		unsigned char *m = mmap(NULL, 3 * page, PROT_READ, MAP_SHARED,
					rb_db, 0);

		if (ASSERT_OK_PTR(m == MAP_FAILED ? NULL : m, "mmap rb")) {
			ASSERT_EQ(run(skel->progs.rb_producer), 0, "rb_producer");
			ASSERT_EQ(__atomic_load_n((__u64 *)(m + page),
						  __ATOMIC_ACQUIRE), 16,
				  "producer_pos advanced");
			ASSERT_EQ(*(__u64 *)(m + 2 * page + HDR_SZ), 0xF00DULL,
				  "record payload");
			munmap(m, 3 * page);
		}
	}

	/* user-ringbuf drain: kernel consumes an injected record */
	if (test__start_subtest("user_ringbuf_drain")) {
		unsigned char *m = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
					MAP_SHARED, urb_db, 0);

		if (ASSERT_OK_PTR(m == MAP_FAILED ? NULL : m, "mmap urb")) {
			*(__u32 *)(m + 2 * page) = 8;
			*(__u64 *)(m + 2 * page + HDR_SZ) = 0xBEEFULL;
			__atomic_store_n((__u64 *)(m + page), 16, __ATOMIC_RELEASE);

			ASSERT_EQ(run(skel->progs.urb_drain), 1, "drain one record");

			__u32 key = 0;
			__u64 val = 0;

			bpf_map_lookup_elem(bpf_map__fd(skel->maps.result),
					    &key, &val);
			ASSERT_EQ(val, 0xBEEFULL, "callback saw payload");
			munmap(m, 3 * page);
		}
	}

cleanup:
	multinode_dmabuf__destroy(skel);
	if (arena_db >= 0)
		close(arena_db);
	if (rb_db >= 0)
		close(rb_db);
	if (urb_db >= 0)
		close(urb_db);
}
