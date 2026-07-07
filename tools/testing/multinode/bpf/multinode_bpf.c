// SPDX-License-Identifier: GPL-2.0
/*
 * libbpf-based selftest for the parts that need real (clang-compiled)
 * BPF programs:
 *  - JIT-inserted arena cache clean (BPF_F_ARENA_CLEAN),
 *  - the dma-buf ringbuf producer (kernel cleans on submit),
 *  - the dma-buf user-ringbuf drain (kernel consumer invalidates).
 *
 * dma-buf maps are not something libbpf creates itself (map_extra is a
 * dma-buf fd, not a user VM start), so each is created here by hand and
 * handed to the loaded program with bpf_map__reuse_fd().
 *
 * Runs as the initramfs /init when PID 1 (mounts, then powers off).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <stdint.h>
#include <linux/dma-heap.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef BPF_F_DMABUF
#define BPF_F_DMABUF		(1U << 20)
#endif
#ifndef BPF_F_ARENA_CLEAN
#define BPF_F_ARENA_CLEAN	(1U << 21)
#endif

#define PAGE 4096u
#define HDR_SZ 8u

static int fails;
#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
	else printf("ok: %s\n", msg); \
} while (0)

static int dmabuf_alloc(unsigned long npages)
{
	int heap = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
	if (heap < 0)
		return -1;
	struct dma_heap_allocation_data a = { .len = (uint64_t)npages * PAGE,
					      .fd_flags = O_RDWR | O_CLOEXEC };
	int ret = ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a);
	close(heap);
	return ret ? -1 : (int)a.fd;
}

/* Create a dma-buf backed map and reuse its fd for the named map in obj. */
static int reuse_dmabuf_map(struct bpf_object *obj, const char *name,
			    enum bpf_map_type type, unsigned int max_entries,
			    unsigned int extra_flags, unsigned long npages,
			    int *dmabuf_out)
{
	int dmabuf = dmabuf_alloc(npages);
	if (dmabuf < 0)
		return -1;

	LIBBPF_OPTS(bpf_map_create_opts, o,
		    .map_flags = BPF_F_DMABUF | extra_flags,
		    .map_extra = (unsigned int)dmabuf);
	int fd = bpf_map_create(type, name, type == BPF_MAP_TYPE_ARENA ? 0 : 0,
				0, max_entries, &o);
	if (fd < 0) {
		close(dmabuf);
		return -1;
	}
	struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
	if (!m || bpf_map__reuse_fd(m, fd)) {
		close(fd);
		close(dmabuf);
		return -1;
	}
	*dmabuf_out = dmabuf;
	return fd;
}

static int run_prog(struct bpf_object *obj, const char *name)
{
	struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
	if (!p)
		return -1;
	unsigned char ctx[8] = {};
	LIBBPF_OPTS(bpf_test_run_opts, t, .ctx_in = ctx, .ctx_size_in = sizeof(ctx));
	if (bpf_prog_test_run_opts(bpf_program__fd(p), &t))
		return -1;
	return (int)t.retval;
}

static void test_arena(struct bpf_object *obj)
{
	printf("== arena JIT clean ==\n");
	struct bpf_program *p = bpf_object__find_program_by_name(obj, "arena_writer");
	int fd = p ? bpf_program__fd(p) : -1;

	static unsigned char jit[65536];
	struct bpf_prog_info info = {};
	info.jited_prog_insns = (unsigned long)jit;
	info.jited_prog_len = sizeof(jit);
	unsigned int len = sizeof(info);
	bool clflush = false;
	if (fd >= 0 && bpf_prog_get_info_by_fd(fd, &info, &len) == 0) {
		unsigned int n = info.jited_prog_len < sizeof(jit) ?
				 info.jited_prog_len : sizeof(jit);
#if defined(__x86_64__)
		/* clflush 0F AE /7 with a memory operand (ModRM.mod != 3) */
		for (unsigned int i = 0; i + 2 < n; i++)
			if (jit[i] == 0x0f && jit[i + 1] == 0xae &&
			    ((jit[i + 2] >> 3) & 7) == 7 &&
			    ((jit[i + 2] >> 6) != 3)) { clflush = true; break; }
#elif defined(__aarch64__)
		/* dc cvac (0xd50b7a20) / dc ivac (0xd5087620) */
		for (unsigned int i = 0; i + 3 < n; i += 4) {
			unsigned int w = jit[i] | jit[i + 1] << 8 |
					 jit[i + 2] << 16 |
					 (unsigned int)jit[i + 3] << 24;
			if ((w & ~0x1fU) == 0xd50b7a20U ||
			    (w & ~0x1fU) == 0xd5087620U) { clflush = true; break; }
		}
#else
		clflush = true;
#endif
	}
	CHECK(clflush, "JIT emitted cache maintenance after arena store");
	CHECK(run_prog(obj, "arena_writer") == 0, "arena_writer runs");
}

static void test_rb_produce(struct bpf_object *obj, int rb_dmabuf)
{
	printf("== dma-buf ringbuf producer ==\n");
	unsigned char *m = mmap(NULL, 3 * PAGE, PROT_READ, MAP_SHARED, rb_dmabuf, 0);
	CHECK(m != MAP_FAILED, "mmap ringbuf dma-buf");
	if (m == MAP_FAILED)
		return;

	CHECK(run_prog(obj, "rb_producer") == 0, "rb_producer runs");

	volatile uint64_t *producer_pos = (volatile uint64_t *)(m + PAGE);
	const volatile unsigned char *data = m + 2 * PAGE;
	CHECK(__atomic_load_n(producer_pos, __ATOMIC_ACQUIRE) == 16,
	      "producer_pos advanced by one 16-byte record");
	uint64_t payload = *(const volatile uint64_t *)(data + HDR_SZ);
	CHECK(payload == 0xF00DULL, "record payload readable from dma-buf");

	munmap(m, 3 * PAGE);
}

static void test_urb_drain(struct bpf_object *obj, int urb_dmabuf)
{
	printf("== dma-buf user-ringbuf drain ==\n");
	unsigned char *m = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE,
				MAP_SHARED, urb_dmabuf, 0);
	CHECK(m != MAP_FAILED, "mmap user-ringbuf dma-buf");
	if (m == MAP_FAILED)
		return;

	/* Inject one record as a (remote) producer would: header length,
	 * payload, then publish producer_pos.
	 */
	volatile uint64_t *producer_pos = (volatile uint64_t *)(m + PAGE);
	unsigned char *data = m + 2 * PAGE;
	*(volatile uint32_t *)(data + 0) = 8;			/* sample_len */
	*(volatile uint64_t *)(data + HDR_SZ) = 0xBEEFULL;	/* payload */
	__atomic_store_n(producer_pos, 16, __ATOMIC_RELEASE);

	int drained = run_prog(obj, "urb_drain");
	CHECK(drained == 1, "drain consumed one record");

	struct bpf_map *rm = bpf_object__find_map_by_name(obj, "result");
	uint32_t key = 0;
	uint64_t val = 0;
	if (rm)
		bpf_map_lookup_elem(bpf_map__fd(rm), &key, &val);
	CHECK(val == 0xBEEFULL, "drain callback saw the record payload");

	munmap(m, 3 * PAGE);
}

int main(void)
{
	bool as_init = getpid() == 1;
	if (as_init) {
		mkdir("/proc", 0755); mkdir("/sys", 0755); mkdir("/dev", 0755);
		mount("none", "/proc", "proc", 0, NULL);
		mount("none", "/sys", "sysfs", 0, NULL);
		mount("none", "/dev", "devtmpfs", 0, NULL);
	}

	struct bpf_object *obj = bpf_object__open_file("/multinode.bpf.o", NULL);
	if (!obj || libbpf_get_error(obj)) {
		printf("FAIL: open multinode.bpf.o\n");
		fails++;
		goto out;
	}

	int arena_db = -1, rb_db = -1, urb_db = -1;
	int arena_fd = reuse_dmabuf_map(obj, "arena", BPF_MAP_TYPE_ARENA, 4,
					BPF_F_MMAPABLE | BPF_F_ARENA_CLEAN, 4, &arena_db);
	int rb_fd = reuse_dmabuf_map(obj, "rb", BPF_MAP_TYPE_RINGBUF, 4096, 0, 3, &rb_db);
	int urb_fd = reuse_dmabuf_map(obj, "urb", BPF_MAP_TYPE_USER_RINGBUF, 4096, 0, 3, &urb_db);
	CHECK(arena_fd >= 0 && rb_fd >= 0 && urb_fd >= 0,
	      "create dma-buf arena + ringbuf + user-ringbuf maps");

	/* arena needs user_vm_start set before a program can reference it;
	 * map_extra is the fd, so establish it by mmap()ing 4 GiB-aligned.
	 */
	if (arena_fd >= 0)
		mmap((void *)0x4000000000ULL, 4 * PAGE, PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_FIXED, arena_fd, 0);

	int err = bpf_object__load(obj);
	CHECK(err == 0, "load programs (arena/ringbuf/drain)");
	if (err)
		goto out;

	test_arena(obj);
	if (rb_db >= 0)
		test_rb_produce(obj, rb_db);
	if (urb_db >= 0)
		test_urb_drain(obj, urb_db);

out:
	printf("\nMULTINODE_BPF: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	if (as_init) {
		fflush(stdout);
		sync();
		reboot(RB_POWER_OFF);
		for (;;) pause();
	}
	return fails ? 1 : 0;
}
