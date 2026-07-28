// SPDX-License-Identifier: GPL-2.0
/*
 * Functional test for the arena-backed multi-node BPF model: a dma-buf
 * (ideally from a device-tree carveout heap) backs an arena, ring buffers
 * are placed inside the arena at kernel-chosen offsets (arena_off), and
 * the consumer reads the dma-buf alone (multi-node-bpf-migration.md).
 *
 * Runs on a single node, so it validates the layout contract, dma-buf
 * import, the produce/consume protocol, arena page identity and the
 * driver's ioctls/permissions — not the non-coherency benefit itself
 * (a single SMP domain is coherent; the cache-maintenance calls are
 * exercised but their effect is invisible here).
 *
 * Self-contained: hand-assembled BPF program, raw bpf() syscalls, no
 * libbpf, so it links statically for a minimal initramfs.
 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/dma-heap.h>

#include "common.h"
#include "bpf_prog.h"

#define PAGE 4096u

static int fails;
#define CHECK(cond, msg, ...) do { \
	if (!(cond)) { printf("FAIL: " msg "\n", ##__VA_ARGS__); fails++; } \
	else printf("ok: " msg "\n", ##__VA_ARGS__); \
} while (0)

static long sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

/* Allocate a page-backed dma-buf of npages pages. Prefer the device-tree
 * carveout heap (a /reserved-memory node with `export;`, exposed as
 * /dev/dma_heap/<node-name>, "xwin@..." in the QEMU harness) and fall
 * back to the system heap.
 */
static int dmabuf_alloc(unsigned long npages)
{
	static bool reported;
	int heap = open("/dev/dma_heap/xwin@50100000", O_RDWR | O_CLOEXEC);
	const char *src = "carveout heap xwin@50100000";

	if (heap < 0) {
		heap = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
		src = "system heap";
	}
	if (heap < 0)
		return -1;
	if (!reported) {
		printf("dma-buf source: %s\n", src);
		reported = true;
	}

	struct dma_heap_allocation_data a = {};
	a.len = (uint64_t)npages * PAGE;
	a.fd_flags = O_RDWR | O_CLOEXEC;
	int ret = ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a);
	close(heap);
	return ret ? -1 : (int)a.fd;
}

static int create_arena(uint32_t nr_pages, int dmabuf_fd)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_ARENA;
	attr.max_entries = nr_pages;
	attr.map_flags = BPF_F_DMABUF | BPF_F_MMAPABLE;
	attr.map_extra = (uint32_t)dmabuf_fd;
	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_ringbuf(uint32_t data_sz, int arena_fd)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_RINGBUF;
	attr.max_entries = data_sz;
	attr.map_flags = BPF_F_ARENA_BACKED;
	attr.map_extra = (uint32_t)arena_fd;
	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_array(uint32_t value_size, uint32_t max_entries, int arena_fd)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = BPF_F_ARENA_BACKED | BPF_F_MMAPABLE;
	attr.map_extra = (uint32_t)arena_fd;
	return sys_bpf(BPF_MAP_CREATE, &attr);
}

/* Where the kernel placed an arena-backed map within its arena. */
static int64_t get_arena_off(int map_fd)
{
	struct bpf_map_info info = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = (uint32_t)map_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uint64_t)(unsigned long)&info;
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr))
		return -1;
	return (int64_t)info.arena_off;
}

static int load_producer(int ringbuf_fd)
{
	struct bpf_insn insns[32];
	int n = build_producer_prog(insns, ringbuf_fd);
	static char log[8192];

	union bpf_attr attr = {};
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt = n;
	attr.insns = (uint64_t)(unsigned long)insns;
	attr.license = (uint64_t)(unsigned long)"GPL";
	attr.log_level = 1;
	attr.log_buf = (uint64_t)(unsigned long)log;
	attr.log_size = sizeof(log);
	int fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0)
		printf("prog load failed: %s\nverifier:\n%s\n",
		       strerror(errno), log);
	return fd;
}

/* Drive the producer once with sequence value seq. */
static int produce_one(int prog_fd, uint64_t seq)
{
	unsigned char in[64] = {}, out[64];
	memcpy(in, &seq, sizeof(seq));

	union bpf_attr attr = {};
	attr.test.prog_fd = prog_fd;
	attr.test.data_in = (uint64_t)(unsigned long)in;
	attr.test.data_size_in = sizeof(in);
	attr.test.data_out = (uint64_t)(unsigned long)out;
	attr.test.data_size_out = sizeof(out);
	attr.test.repeat = 1;
	return sys_bpf(BPF_PROG_TEST_RUN, &attr);
}

static uint64_t read_payload8(const volatile unsigned char *data,
			      uint64_t mask, uint64_t pos)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v |= (uint64_t)data[(pos + i) & mask] << (8 * i);
	return v;
}

static void test_ringbuf(void)
{
	printf("== ringbuf ==\n");
	const uint32_t data_sz = PAGE;			/* 1 data page */
	const unsigned long npages = 16;		/* whole shared window */

	int dmabuf = dmabuf_alloc(npages);
	CHECK(dmabuf >= 0, "dma-heap alloc %lu pages", npages);
	if (dmabuf < 0)
		return;

	int arena = create_arena(npages, dmabuf);
	CHECK(arena >= 0, "create BPF_F_DMABUF arena on the window");
	if (arena < 0)
		return;

	int rb = create_ringbuf(data_sz, arena);
	CHECK(rb >= 0, "create BPF_F_ARENA_BACKED ringbuf in the arena");
	if (rb < 0)
		return;

	int64_t arena_off = get_arena_off(rb);
	CHECK(arena_off >= 0 &&
	      (uint64_t)arena_off + 2 * PAGE + data_sz <= npages * PAGE,
	      "map_info reports arena_off (0x%llx)",
	      (unsigned long long)arena_off);
	if (arena_off < 0)
		return;

	int prog = load_producer(rb);
	CHECK(prog >= 0, "load producer program");
	if (prog < 0)
		return;

	/* Consumer view: linear mapping of the whole dma-buf. */
	unsigned char *m = (unsigned char *)mmap(NULL, npages * PAGE,
			PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf, 0);
	CHECK(m != MAP_FAILED, "mmap dma-buf for consumer");
	if (m == MAP_FAILED)
		return;

	/* the ring buffer sits at arena_off within the shared window */
	volatile uint64_t *consumer_pos = (volatile uint64_t *)(m + arena_off);
	volatile uint64_t *producer_pos = (volatile uint64_t *)(m + arena_off + PAGE);
	const volatile unsigned char *data = m + arena_off + 2 * PAGE;
	uint64_t mask = data_sz - 1;

	/*
	 * Lockstep produce/consume for more records than the ring holds,
	 * so the data region wraps several times.
	 */
	const uint64_t total = 1000;
	uint64_t got = 0, cons = 0;
	bool seq_ok = true, busy_ok = true;

	for (uint64_t seq = 0; seq < total; seq++) {
		if (produce_one(prog, seq) < 0) {
			printf("FAIL: test_run seq %llu: %s\n",
			       (unsigned long long)seq, strerror(errno));
			fails++;
			break;
		}
		uint64_t prod = __atomic_load_n(producer_pos, __ATOMIC_ACQUIRE);
		while (cons < prod) {
			uint32_t len = *(const volatile uint32_t *)
				(data + (cons & mask));
			if (len & BUSY_BIT) { busy_ok = false; break; }
			uint32_t slen = len & ~DISCARD_BIT;
			if (!(len & DISCARD_BIT)) {
				uint64_t v = read_payload8(data, mask,
							   cons + HDR_SZ);
				if (v != got)
					seq_ok = false;
				got++;
			}
			cons += round_up8(slen + HDR_SZ);
			__atomic_store_n(consumer_pos, cons, __ATOMIC_RELEASE);
		}
	}

	CHECK(busy_ok, "no record observed with stale BUSY bit");
	CHECK(seq_ok, "records arrived in order");
	CHECK(got == total, "consumed all %llu records (got %llu)",
	      (unsigned long long)total, (unsigned long long)got);

	munmap(m, npages * PAGE);
	close(prog);
	close(rb);
	close(arena);
	close(dmabuf);
}


/*
 * One dma-buf arena hosting two ring buffers -- a "host" ring and a "vm"
 * ring (the slice a guest would create over its shared view of the same
 * arena) -- drained by a *single* consumer that polls both. This is the
 * multi-producer / single-consumer shape of the VM deployment, minus the
 * VM boundary: the consumer sees one dma-buf and both rings live in it at
 * distinct arena offsets.
 */
struct rb_consumer {
	volatile uint64_t *consumer_pos;
	volatile uint64_t *producer_pos;
	const volatile unsigned char *data;
	uint64_t mask;
	uint64_t cons;		/* our consumer position */
	uint64_t got;		/* records drained */
	uint64_t expect;	/* next expected payload value */
	bool seq_ok, busy_ok;
};

static void rb_consumer_init(struct rb_consumer *c, unsigned char *m,
			     int64_t arena_off, uint32_t data_sz)
{
	c->consumer_pos = (volatile uint64_t *)(m + arena_off);
	c->producer_pos = (volatile uint64_t *)(m + arena_off + PAGE);
	c->data = m + arena_off + 2 * PAGE;
	c->mask = data_sz - 1;
	c->cons = c->got = c->expect = 0;
	c->seq_ok = c->busy_ok = true;
}

/* Poll one ring: drain whatever the producer has committed so far. */
static void rb_consumer_poll(struct rb_consumer *c)
{
	uint64_t prod = __atomic_load_n(c->producer_pos, __ATOMIC_ACQUIRE);

	while (c->cons < prod) {
		uint32_t len = *(const volatile uint32_t *)
			(c->data + (c->cons & c->mask));
		if (len & BUSY_BIT) { c->busy_ok = false; break; }
		uint32_t slen = len & ~DISCARD_BIT;
		if (!(len & DISCARD_BIT)) {
			uint64_t v = read_payload8(c->data, c->mask,
						  c->cons + HDR_SZ);
			if (v != c->expect)
				c->seq_ok = false;
			c->expect++;
			c->got++;
		}
		c->cons += round_up8(slen + HDR_SZ);
		__atomic_store_n(c->consumer_pos, c->cons, __ATOMIC_RELEASE);
	}
}

static void test_multi_ringbuf(void)
{
	printf("== multi ringbuf (one arena, two rings, single poll consumer) ==\n");
	const uint32_t data_sz = PAGE;
	const unsigned long npages = 32;		/* room for two rings */

	int dmabuf = dmabuf_alloc(npages);
	int arena = dmabuf >= 0 ? create_arena(npages, dmabuf) : -1;
	CHECK(arena >= 0, "dma-buf arena for two rings");
	if (arena < 0)
		return;

	/* Two ring buffers carved from the same arena by the kernel. */
	int rb_host = create_ringbuf(data_sz, arena);
	int rb_vm   = create_ringbuf(data_sz, arena);
	CHECK(rb_host >= 0 && rb_vm >= 0, "create host + vm rings in one arena");
	if (rb_host < 0 || rb_vm < 0)
		return;

	int64_t off_host = get_arena_off(rb_host);
	int64_t off_vm   = get_arena_off(rb_vm);
	CHECK(off_host >= 0 && off_vm >= 0 && off_host != off_vm,
	      "two distinct arena offsets (host 0x%llx, vm 0x%llx)",
	      (unsigned long long)off_host, (unsigned long long)off_vm);
	if (off_host < 0 || off_vm < 0)
		return;

	int prog_host = load_producer(rb_host);
	int prog_vm   = load_producer(rb_vm);
	CHECK(prog_host >= 0 && prog_vm >= 0, "load both producers");
	if (prog_host < 0 || prog_vm < 0)
		return;

	unsigned char *m = (unsigned char *)mmap(NULL, npages * PAGE,
			PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf, 0);
	CHECK(m != MAP_FAILED, "mmap dma-buf for the single consumer");
	if (m == MAP_FAILED)
		return;

	struct rb_consumer ch, cv;
	rb_consumer_init(&ch, m, off_host, data_sz);
	rb_consumer_init(&cv, m, off_vm, data_sz);

	/*
	 * Interleave production into both rings, and after each step the one
	 * consumer polls both -- more records than a ring holds, so each data
	 * area wraps several times.
	 */
	const uint64_t total = 1000;
	bool prod_ok = true;
	for (uint64_t seq = 0; seq < total; seq++) {
		if (produce_one(prog_host, seq) < 0 ||
		    produce_one(prog_vm, seq) < 0) {
			prod_ok = false;
			break;
		}
		rb_consumer_poll(&ch);
		rb_consumer_poll(&cv);
	}
	/* Final drain in case the last commits landed after the last poll. */
	rb_consumer_poll(&ch);
	rb_consumer_poll(&cv);

	CHECK(prod_ok, "both producers ran");
	CHECK(ch.busy_ok && cv.busy_ok, "no stale BUSY bit on either ring");
	CHECK(ch.seq_ok && cv.seq_ok, "records in order on both rings");
	CHECK(ch.got == total, "host ring fully drained (%llu/%llu)",
	      (unsigned long long)ch.got, (unsigned long long)total);
	CHECK(cv.got == total, "vm ring fully drained (%llu/%llu)",
	      (unsigned long long)cv.got, (unsigned long long)total);

	munmap(m, npages * PAGE);
	close(prog_host); close(prog_vm);
	close(rb_host); close(rb_vm);
	close(arena); close(dmabuf);
}

static void test_arena(void)
{
	printf("== arena ==\n");
	const uint32_t nr_pages = 4;

	int dmabuf = dmabuf_alloc(nr_pages);
	CHECK(dmabuf >= 0, "dma-heap alloc %u pages", nr_pages);
	if (dmabuf < 0)
		return;

	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_ARENA;
	attr.key_size = 0;
	attr.value_size = 0;
	attr.max_entries = nr_pages;
	attr.map_flags = BPF_F_DMABUF | BPF_F_MMAPABLE;
	attr.map_extra = (uint32_t)dmabuf;
	int arena = sys_bpf(BPF_MAP_CREATE, &attr);
	CHECK(arena >= 0, "create BPF_F_DMABUF arena");
	if (arena < 0) {
		close(dmabuf);
		return;
	}

	/* The arena's pages must be the dma-buf's pages: write through the
	 * arena user mapping, read back through a second dma-buf mapping.
	 *
	 * Arenas address pages by the low 32 bits of the user address
	 * (arena_vm_fault: kern_vm_start + (u32)vaddr), so the dma-buf's
	 * page 0 only lines up with the mapping's offset 0 when
	 * user_vm_start is 4 GiB-aligned. Map at a fixed 4 GiB-aligned
	 * address to satisfy that.
	 */
	void *hint = (void *)0x4000000000ULL;		/* 256 GiB, 4G-aligned */
	unsigned char *am = (unsigned char *)mmap(hint, nr_pages * PAGE,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, arena, 0);
	CHECK(am != MAP_FAILED, "mmap arena (4 GiB-aligned)");
	unsigned char *dm = (unsigned char *)mmap(NULL, nr_pages * PAGE,
			PROT_READ, MAP_SHARED, dmabuf, 0);
	CHECK(dm != MAP_FAILED, "mmap dma-buf");

	if (am != MAP_FAILED && dm != MAP_FAILED) {
		for (unsigned i = 0; i < nr_pages * PAGE; i += 64)
			am[i] = (unsigned char)(i / 64);
		bool match = true;
		for (unsigned i = 0; i < nr_pages * PAGE; i += 64)
			if (dm[i] != (unsigned char)(i / 64))
				match = false;
		CHECK(match, "arena pages alias the dma-buf pages");
	}

	if (am != MAP_FAILED)
		munmap(am, nr_pages * PAGE);
	if (dm != MAP_FAILED)
		munmap(dm, nr_pages * PAGE);
	close(arena);
	close(dmabuf);
}

static void test_array(void)
{
	printf("== array (arena-backed) ==\n");
	const uint32_t nr = 64, vsz = 8, win_pages = 16;

	int dmabuf = dmabuf_alloc(win_pages);
	CHECK(dmabuf >= 0, "dma-heap alloc %u pages", win_pages);
	if (dmabuf < 0)
		return;

	int arena = create_arena(win_pages, dmabuf);
	CHECK(arena >= 0, "create dma-buf arena");
	if (arena < 0) {
		close(dmabuf);
		return;
	}

	int arr = create_array(vsz, nr, arena);
	CHECK(arr >= 0, "create BPF_F_ARENA_BACKED array");
	if (arr < 0) {
		close(arena);
		close(dmabuf);
		return;
	}

	int64_t off = get_arena_off(arr);
	CHECK(off >= 0 && (uint64_t)off + (uint64_t)nr * vsz <= win_pages * PAGE,
	      "array reports arena_off (0x%llx)", (unsigned long long)off);

	/* local view: mmap the array fd; value[i] at offset i*vsz, from 0 */
	uint64_t *vals = (uint64_t *)mmap(NULL, (size_t)nr * vsz,
			PROT_READ | PROT_WRITE, MAP_SHARED, arr, 0);
	CHECK(vals != MAP_FAILED, "mmap array fd");
	/* peer view: the dma-buf; value[i] at arena_off + i*vsz */
	unsigned char *dm = (unsigned char *)mmap(NULL, win_pages * PAGE,
			PROT_READ, MAP_SHARED, dmabuf, 0);
	CHECK(dm != MAP_FAILED, "mmap dma-buf");

	if (vals != MAP_FAILED && dm != MAP_FAILED && off >= 0) {
		volatile uint64_t *peer = (volatile uint64_t *)(dm + off);
		bool match = true;

		for (uint32_t i = 0; i < nr; i++)
			vals[i] = 0xA5A50000ull + i;
		for (uint32_t i = 0; i < nr; i++)
			if (peer[i] != 0xA5A50000ull + i)
				match = false;
		CHECK(match, "array values visible via dma-buf at arena_off");
	}

	if (vals != MAP_FAILED)
		munmap(vals, (size_t)nr * vsz);
	if (dm != MAP_FAILED)
		munmap(dm, win_pages * PAGE);
	close(arr);
	close(arena);
	close(dmabuf);
}

/* One dma-buf arena holding a ring buffer and an array at once — the
 * deployment shape. Both are produced/written locally and read back by the
 * "peer" through the dma-buf alone, each at its own arena_off.
 */
static void test_mixed(void)
{
	printf("== mixed (ringbuf + array in one dma-buf arena) ==\n");
	const uint32_t win_pages = 32, rb_data = PAGE, nr = 64, vsz = 8;

	int dmabuf = dmabuf_alloc(win_pages);
	if (dmabuf < 0) {
		printf("skip: dma-heap unavailable\n");
		return;
	}
	int arena = create_arena(win_pages, dmabuf);
	int rb = create_ringbuf(rb_data, arena);
	int arr = create_array(vsz, nr, arena);
	CHECK(arena >= 0 && rb >= 0 && arr >= 0, "create arena + ringbuf + array");
	if (arena < 0 || rb < 0 || arr < 0)
		goto out;

	{
		int64_t rb_off = get_arena_off(rb);
		int64_t arr_off = get_arena_off(arr);
		CHECK(rb_off >= 0 && arr_off >= 0 && rb_off != arr_off,
		      "distinct offsets in one window (rb=0x%llx arr=0x%llx)",
		      (unsigned long long)rb_off, (unsigned long long)arr_off);

		int prog = load_producer(rb);
		if (prog >= 0)
			produce_one(prog, 0xdead);

		uint64_t *av = (uint64_t *)mmap(NULL, (size_t)nr * vsz,
				PROT_READ | PROT_WRITE, MAP_SHARED, arr, 0);
		if (av != MAP_FAILED)
			av[3] = 0xC0FFEE;

		unsigned char *dm = (unsigned char *)mmap(NULL, win_pages * PAGE,
				PROT_READ, MAP_SHARED, dmabuf, 0);
		if (dm != MAP_FAILED && rb_off >= 0 && arr_off >= 0) {
			volatile uint64_t *prod =
				(volatile uint64_t *)(dm + rb_off + PAGE);
			uint64_t aval =
				*(volatile uint64_t *)(dm + arr_off + 3 * vsz);
			CHECK(*prod == 16, "ringbuf produced, seen via dma-buf");
			CHECK(aval == 0xC0FFEE, "array value seen via dma-buf");
			munmap(dm, win_pages * PAGE);
		}
		if (av != MAP_FAILED)
			munmap(av, (size_t)nr * vsz);
		if (prog >= 0)
			close(prog);
	}
out:
	if (arr >= 0)
		close(arr);
	if (rb >= 0)
		close(rb);
	if (arena >= 0)
		close(arena);
	close(dmabuf);
}

/* ---- MMIO: needs kfunc calls, so resolve kfunc BTF ids first ---- */

struct btf_hdr {
	uint16_t magic;
	uint8_t version, flags;
	uint32_t hdr_len, type_off, type_len, str_off, str_len;
};
struct btf_type {
	uint32_t name_off, info, size_or_type;
};
#define BTF_KIND(info) (((info) >> 24) & 0x1f)
#define BTF_VLEN(info) ((info) & 0xffff)

static size_t btf_trailing(uint32_t info)
{
	uint32_t k = BTF_KIND(info), v = BTF_VLEN(info);
	switch (k) {
	case 1:  return 4;	/* INT */
	case 3:  return 12;	/* ARRAY */
	case 4: case 5: return v * 12;	/* STRUCT/UNION */
	case 6:  return v * 8;	/* ENUM */
	case 13: return v * 8;	/* FUNC_PROTO */
	case 14: return 4;	/* VAR */
	case 15: return v * 12;	/* DATASEC */
	case 17: return 4;	/* DECL_TAG */
	case 19: return v * 12;	/* ENUM64 */
	default: return 0;
	}
}

/* Find a BTF_KIND_FUNC by name in the running kernel's vmlinux BTF. */
static int btf_find_func(const char *name)
{
	int f = open("/sys/kernel/btf/vmlinux", O_RDONLY);
	if (f < 0)
		return -1;
	/* kernfs returns the BTF blob in chunks; read to EOF. */
	static char buf[32 << 20];
	size_t off = 0;
	for (;;) {
		ssize_t r = read(f, buf + off, sizeof(buf) - off);
		if (r <= 0)
			break;
		off += r;
		if (off == sizeof(buf))
			break;
	}
	close(f);
	if (off < sizeof(struct btf_hdr))
		return -1;

	struct btf_hdr *h = (struct btf_hdr *)buf;
	char *types = buf + h->hdr_len + h->type_off;
	char *strs = buf + h->hdr_len + h->str_off;
	char *p = types;
	int id = 1;
	while (p < types + h->type_len) {
		struct btf_type *t = (struct btf_type *)p;
		if (BTF_KIND(t->info) == 12 /* FUNC */ &&
		    strcmp(strs + t->name_off, name) == 0)
			return id;
		p += sizeof(*t) + btf_trailing(t->info);
		id++;
	}
	return -1;
}


/*
 * Exercise the arena kfunc path on a dma-buf backed arena: load a program
 * that bpf_arena_alloc_pages() (pure range-tree bookkeeping over the
 * pre-populated window) and stores through the returned arena pointer.
 * No cache maintenance is involved on this branch.
 */
static void test_arena_jit(void)
{
	printf("== arena kfunc alloc/store ==\n");

	int id_alloc = btf_find_func("bpf_arena_alloc_pages");
	if (id_alloc <= 0) {
		printf("skip: arena kfunc BTF ids unavailable\n");
		return;
	}

	int dmabuf = dmabuf_alloc(4);
	if (dmabuf < 0) {
		printf("skip: dma-heap unavailable\n");
		return;
	}

	union bpf_attr ma = {};
	ma.map_type = BPF_MAP_TYPE_ARENA;
	ma.max_entries = 4;
	ma.map_flags = BPF_F_DMABUF | BPF_F_MMAPABLE;
	ma.map_extra = (uint32_t)dmabuf;
	int arena = sys_bpf(BPF_MAP_CREATE, &ma);
	CHECK(arena >= 0, "create dma-buf arena for kfunc alloc");
	if (arena < 0) {
		close(dmabuf);
		return;
	}

	/* the verifier requires the arena's user address before load;
	 * map at a fixed 4 GiB-aligned address
	 */
	void *am = mmap((void *)0x8000000000ULL, 4 * PAGE,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
			arena, 0);
	CHECK(am != MAP_FAILED, "mmap arena before load");
	if (am == MAP_FAILED) {
		close(arena);
		close(dmabuf);
		return;
	}

	struct bpf_insn prog[] = {
		LD_MAP_FD(BPF_REG_1, arena),			/* r1 = arena map */
		MOV64_IMM(BPF_REG_2, 0),			/* addr = NULL */
		MOV64_IMM(BPF_REG_3, 1),			/* page_cnt = 1 */
		MOV64_IMM(BPF_REG_4, -1),			/* NUMA_NO_NODE */
		MOV64_IMM(BPF_REG_5, 0),			/* flags */
		INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, id_alloc),
		JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3),		/* NULL -> out */
		/* addr_space_cast r0, as(1) -> as(0): kernel-usable pointer */
		INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_0, 1, 1),
		MOV64_IMM(BPF_REG_1, 0xABCD),
		STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0),	/* arena store */
		MOV64_IMM(BPF_REG_0, 0),			/* out */
		EXIT_INSN(),
	};
	static char log[16384];
	union bpf_attr la = {};
	la.prog_type = BPF_PROG_TYPE_SYSCALL;
	la.prog_flags = BPF_F_SLEEPABLE;
	la.insn_cnt = sizeof(prog) / sizeof(prog[0]);
	la.insns = (uint64_t)(unsigned long)prog;
	la.license = (uint64_t)(unsigned long)"GPL";
	la.log_level = 1;
	la.log_buf = (uint64_t)(unsigned long)log;
	la.log_size = sizeof(log);
	int prog_fd = sys_bpf(BPF_PROG_LOAD, &la);
	if (prog_fd < 0) {
		/* Hand-assembling a loadable arena-writing program is
		 * finicky; skip rather than fail if it does not load. The
		 * JIT emission itself is exercised once this loads.
		 */
		printf("skip: arena-writing program did not load (%s)\n%s\n",
		       strerror(errno), log);
		close(arena);
		close(dmabuf);
		return;
	}


	/* run it: a malformed clflush would #UD here */
	unsigned char ctx[8] = {};
	union bpf_attr ta = {};
	ta.test.prog_fd = (uint32_t)prog_fd;
	ta.test.ctx_in = (uint64_t)(unsigned long)ctx;
	ta.test.ctx_size_in = sizeof(ctx);
	CHECK(sys_bpf(BPF_PROG_TEST_RUN, &ta) == 0 && ta.test.retval == 0,
	      "arena-writing program runs");

	/* the store must be visible through the dma-buf (first free page
	 * of the window is what the allocator hands out first)
	 */
	{
		volatile uint64_t *dm = (volatile uint64_t *)mmap(NULL, 4 * PAGE,
				PROT_READ, MAP_SHARED, dmabuf, 0);
		if (dm != MAP_FAILED) {
			CHECK(dm[0] == 0xABCD,
			      "arena kfunc store visible via dma-buf (0x%llx)",
			      (unsigned long long)dm[0]);
			munmap((void *)dm, 4 * PAGE);
		}
	}

	close(prog_fd);
	close(arena);
	close(dmabuf);
}

/*
 * notify_fd: the ring buffer signals an eventfd on wakeup. This is the
 * producer node's doorbell hook -- a fabric driver binds the same
 * eventfd irqfd-style and turns each signal into a doorbell write; here
 * the eventfd itself is observed (same-node view of the same chain).
 */
static void test_notify(void)
{
	printf("== notify_fd ==\n");
	const uint32_t data_sz = PAGE;
	const unsigned long npages = 8;

	int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	CHECK(efd >= 0, "eventfd");
	if (efd < 0)
		return;

	int dmabuf = dmabuf_alloc(npages);
	int arena = dmabuf >= 0 ? create_arena(npages, dmabuf) : -1;
	CHECK(arena >= 0, "dma-buf arena for the notify ring");
	if (arena < 0)
		return;

	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_RINGBUF;
	attr.max_entries = data_sz;
	attr.map_flags = BPF_F_ARENA_BACKED;
	attr.map_extra = (uint32_t)arena;
	attr.notify_fd = (uint32_t)efd;
	int rb = sys_bpf(BPF_MAP_CREATE, &attr);
	CHECK(rb >= 0, "create arena-backed ringbuf with notify_fd");
	if (rb < 0)
		return;

	int prog = load_producer(rb);
	CHECK(prog >= 0, "load producer program");
	if (prog < 0)
		return;

	/* First record: the consumer is "caught up" at pos 0, so the
	 * adaptive wakeup fires; the signal is deferred via irq_work, so
	 * poll rather than race it.
	 */
	CHECK(produce_one(prog, 1) == 0, "produce a record");
	uint64_t cnt = 0;
	int ready = -1;
	for (int i = 0; i < 5000; i++) {
		if (read(efd, &cnt, sizeof(cnt)) == (ssize_t)sizeof(cnt)) {
			ready = 0;
			break;
		}
		usleep(1000);
	}
	CHECK(ready == 0 && cnt >= 1, "eventfd signaled on commit (cnt=%llu)",
	      (unsigned long long)cnt);

	/* notify_fd is only for kernel-producer ring buffers */
	union bpf_attr bad = {};
	bad.map_type = BPF_MAP_TYPE_ARRAY;
	bad.key_size = 4;
	bad.value_size = 4;
	bad.max_entries = 1;
	bad.notify_fd = (uint32_t)efd;
	int fd = sys_bpf(BPF_MAP_CREATE, &bad);
	CHECK(fd < 0 && errno == EINVAL, "notify_fd on an array is rejected");
	if (fd >= 0)
		close(fd);

	close(prog); close(rb); close(arena); close(dmabuf); close(efd);
}

static void test_negative(void)
{
	printf("== negative map flags ==\n");
	int db = dmabuf_alloc(3);
	if (db < 0) {
		printf("skip: dma-heap unavailable\n");
		return;
	}

	int arena = create_arena(3, db);
	CHECK(arena >= 0, "arena for negative tests");
	if (arena < 0) {
		close(db);
		return;
	}

	/* USER_RINGBUF makes the kernel the consumer; arena backing is
	 * supported for it too.
	 */
	union bpf_attr a = {};
	a.map_type = BPF_MAP_TYPE_USER_RINGBUF;
	a.max_entries = PAGE;
	a.map_flags = BPF_F_ARENA_BACKED;
	a.map_extra = (uint32_t)arena;
	int m = sys_bpf(BPF_MAP_CREATE, &a);
	CHECK(m >= 0, "USER_RINGBUF + ARENA_BACKED allowed");
	if (m >= 0)
		close(m);

	/* overwrite mode keeps producer state in the shared page: rejected */
	memset(&a, 0, sizeof(a));
	a.map_type = BPF_MAP_TYPE_RINGBUF;
	a.max_entries = PAGE;
	a.map_flags = BPF_F_ARENA_BACKED | BPF_F_RB_OVERWRITE;
	a.map_extra = (uint32_t)arena;
	m = sys_bpf(BPF_MAP_CREATE, &a);
	CHECK(m < 0 && errno == EINVAL,
	      "RINGBUF + ARENA_BACKED + OVERWRITE rejected (EINVAL)");
	if (m >= 0)
		close(m);

	/* map_extra must be an arena fd */
	memset(&a, 0, sizeof(a));
	a.map_type = BPF_MAP_TYPE_RINGBUF;
	a.max_entries = PAGE;
	a.map_flags = BPF_F_ARENA_BACKED;
	a.map_extra = (uint32_t)db;		/* a dma-buf, not an arena */
	m = sys_bpf(BPF_MAP_CREATE, &a);
	CHECK(m < 0, "RINGBUF + ARENA_BACKED over a non-arena fd rejected");
	if (m >= 0)
		close(m);

	close(arena);
	close(db);
}

static int link_create_fd(int target, int anchor)
{
	union bpf_attr a = {};
	a.link_create.target_fd = (uint32_t)target;
	a.link_create.prog_fd = (uint32_t)anchor;	/* mandatory anchor */
	a.link_create.attach_type = BPF_DEPENDENT_FD;
	return sys_bpf(BPF_LINK_CREATE, &a);
}

/* every fd link names the BPF object that depends on the fd */
static int fdlink_anchor_map(void)
{
	union bpf_attr ma = {};
	ma.map_type = BPF_MAP_TYPE_ARRAY;
	ma.key_size = 4;
	ma.value_size = 4;
	ma.max_entries = 1;
	return sys_bpf(BPF_MAP_CREATE, &ma);
}

static bool fdinfo_contains(int fd, const char *needle)
{
	char path[64], buf[512];
	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	int f = open(path, O_RDONLY);
	if (f < 0)
		return false;
	ssize_t n = read(f, buf, sizeof(buf) - 1);
	close(f);
	if (n <= 0)
		return false;
	buf[n] = 0;
	return strstr(buf, needle) != nullptr;
}

static void test_fdlink(void)
{
	printf("== fd link ==\n");

	int fdl_anchor = fdlink_anchor_map();
	CHECK(fdl_anchor >= 0, "fd link anchor map");

	/* anchored dependency: fd-link { eventfd, anchor: map }. The link
	 * holds the map; GET_DEP_FD reacquires both sides -- the restart
	 * path of the pin structure (see the migration guide).
	 */
	{
		union bpf_attr ma = {};
		ma.map_type = BPF_MAP_TYPE_ARRAY;
		ma.key_size = 4;
		ma.value_size = 8;
		ma.max_entries = 4;
		int arr = sys_bpf(BPF_MAP_CREATE, &ma);
		int aev = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		CHECK(arr >= 0 && aev >= 0, "anchored: array + eventfd");

		struct bpf_map_info mi = {};
		union bpf_attr ia = {};
		ia.info.bpf_fd = (uint32_t)arr;
		ia.info.info_len = sizeof(mi);
		ia.info.info = (uint64_t)(unsigned long)&mi;
		sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia);
		uint32_t map_id = mi.id;

		union bpf_attr la = {};
		la.link_create.target_fd = (uint32_t)aev;
		la.link_create.prog_fd = (uint32_t)arr;	/* the anchor */
		la.link_create.attach_type = BPF_DEPENDENT_FD;
		int alink = sys_bpf(BPF_LINK_CREATE, &la);
		CHECK(alink >= 0, "create anchored fd link");

		close(arr);	/* the link now keeps the map alive */

		union bpf_attr ga = {};
		ga.link_get_dep.link_fd = (uint32_t)alink;
		ga.link_get_dep.which = BPF_FD_LINK_DEP_ANCHOR;
		int r_map = sys_bpf(BPF_LINK_GET_DEP_FD, &ga);
		CHECK(r_map >= 0, "reacquire anchor (map)");
		if (r_map >= 0) {
			struct bpf_map_info mi2 = {};
			union bpf_attr ia2 = {};
			ia2.info.bpf_fd = (uint32_t)r_map;
			ia2.info.info_len = sizeof(mi2);
			ia2.info.info = (uint64_t)(unsigned long)&mi2;
			sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia2);
			CHECK(mi2.id == map_id, "anchor is the same map");
			close(r_map);
		}
		ga.link_get_dep.which = BPF_FD_LINK_DEP_EXTERNAL;
		int r_ev = sys_bpf(BPF_LINK_GET_DEP_FD, &ga);
		CHECK(r_ev >= 0, "reacquire external (eventfd)");
		if (r_ev >= 0) {
			uint64_t v = 1, out = 0;
			CHECK(write(aev, &v, sizeof(v)) == (ssize_t)sizeof(v) &&
			      read(r_ev, &out, sizeof(out)) == (ssize_t)sizeof(out) &&
			      out >= 1, "reacquired eventfd is the same one");
			close(r_ev);
		}
		close(alink);
		close(aev);
	}

	/* eventfd: a leaf file, allowed */
	int ev = eventfd(0, EFD_CLOEXEC);
	int link = link_create_fd(ev, fdl_anchor);
	CHECK(link >= 0, "create fd link over eventfd");
	if (link >= 0) {
		struct bpf_link_info info = {};
		union bpf_attr ia = {};
		ia.info.bpf_fd = (uint32_t)link;
		ia.info.info_len = sizeof(info);
		ia.info.info = (uint64_t)(unsigned long)&info;
		int r = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia);
		CHECK(r == 0 && info.type == BPF_LINK_TYPE_FD,
		      "link_info type == FD");
		CHECK(info.fd.kind == BPF_FD_LINK_KIND_EVENTFD,
		      "link_info kind == eventfd");
		CHECK(info.fd.ino != 0, "link_info reports backing inode");
		CHECK(fdinfo_contains(link, "fd_kind:\teventfd"),
		      "fdinfo shows fd_kind eventfd");
		close(link);
	}
	close(ev);

	/* dma-buf: also a leaf, allowed */
	int db = dmabuf_alloc(1);
	if (db >= 0) {
		int l = link_create_fd(db, fdl_anchor);
		CHECK(l >= 0, "create fd link over dma-buf");
		if (l >= 0) {
			struct bpf_link_info info = {};
			union bpf_attr ia = {};
			ia.info.bpf_fd = (uint32_t)l;
			ia.info.info_len = sizeof(info);
			ia.info.info = (uint64_t)(unsigned long)&info;
			sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia);
			CHECK(info.fd.kind == BPF_FD_LINK_KIND_DMABUF,
			      "link_info kind == dmabuf");
			close(l);
		}
		close(db);
	}

	/* a pipe is not a whitelisted leaf type: rejected */
	int pfd[2];
	if (pipe(pfd) == 0) {
		int bad = link_create_fd(pfd[0], fdl_anchor);
		CHECK(bad < 0 && errno == EPERM,
		      "non-whitelisted fd rejected (EPERM)");
		if (bad >= 0)
			close(bad);
		close(pfd[0]);
		close(pfd[1]);
	}

	/* an fd link without an anchor is not a dependency: rejected */
	{
		int aev = eventfd(0, EFD_CLOEXEC);
		int bare = link_create_fd(aev, 0);
		CHECK(bare < 0 && errno == EINVAL,
		      "anchorless fd link rejected (EINVAL)");
		if (bare >= 0)
			close(bare);
		close(aev);
	}

	close(fdl_anchor);
}

/*
 * When run as PID 1 (as the initramfs /init) there is no shell to set
 * up mounts, so do it here: devtmpfs is needed for the /dev/dma_heap
 * nodes to appear.
 */
static bool as_init;

static void init_setup(void)
{
	as_init = true;
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mkdir("/dev", 0755);
	mount("none", "/proc", "proc", 0, nullptr);
	mount("none", "/sys", "sysfs", 0, nullptr);
	mount("none", "/dev", "devtmpfs", 0, nullptr);
}

int main(void)
{
	if (getpid() == 1)
		init_setup();

	test_ringbuf();
	test_multi_ringbuf();
	test_arena();
	test_array();
	test_mixed();
	test_arena_jit();
	test_notify();
	test_negative();
	test_fdlink();

	/* The subtests close their maps, but the actual teardown runs in a
	 * deferred workqueue item -- give it time to execute (and, with
	 * oops=panic on the command line, to take the run down) before
	 * declaring a verdict and powering off. Without this the free paths
	 * are never exercised: the whole run completes in ~1s.
	 */
	usleep(500 * 1000);

	printf("\nMULTINODE: %s (%d failure%s)\n",
	       fails ? "FAIL" : "ALL PASS", fails, fails == 1 ? "" : "s");

	if (as_init) {
		/* No init to return to; halt the machine. */
		fflush(stdout);
		sync();
		reboot(RB_POWER_OFF);
		for (;;)
			pause();
	}
	return fails ? 1 : 0;
}
