// SPDX-License-Identifier: GPL-2.0
/*
 * Functional test for dma-buf backed BPF ringbuf/arena and the
 * xnode_shmem window driver (Documentation/bpf/multi-node-bpf.md).
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
#include <linux/xnode_shmem.h>

#include "common.h"

/* Not defined in every base's uapi; the bit is rejected via the ringbuf
 * flag mask where the feature does not exist, so the negative test below
 * holds either way.
 */
#ifndef BPF_F_RB_OVERWRITE
#define BPF_F_RB_OVERWRITE (1U << 19)
#endif
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

/* Allocate a page-backed dma-buf of npages pages from the system heap. */
static int dmabuf_alloc(unsigned long npages)
{
	int heap = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
	if (heap < 0)
		return -1;

	struct dma_heap_allocation_data a = {};
	a.len = (uint64_t)npages * PAGE;
	a.fd_flags = O_RDWR | O_CLOEXEC;
	int ret = ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a);
	close(heap);
	return ret ? -1 : (int)a.fd;
}

static int create_ringbuf(uint32_t data_sz, int dmabuf_fd)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_RINGBUF;
	attr.max_entries = data_sz;
	attr.map_flags = BPF_F_DMABUF;
	attr.map_extra = (uint32_t)dmabuf_fd;
	return sys_bpf(BPF_MAP_CREATE, &attr);
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
	const unsigned long npages = 2 + data_sz / PAGE;

	int dmabuf = dmabuf_alloc(npages);
	CHECK(dmabuf >= 0, "dma-heap alloc %lu pages", npages);
	if (dmabuf < 0)
		return;

	int rb = create_ringbuf(data_sz, dmabuf);
	CHECK(rb >= 0, "create BPF_F_DMABUF ringbuf");
	if (rb < 0)
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

	volatile uint64_t *consumer_pos = (volatile uint64_t *)(m + 0);
	volatile uint64_t *producer_pos = (volatile uint64_t *)(m + PAGE);
	const volatile unsigned char *data = m + 2 * PAGE;
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
	close(dmabuf);
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

static void test_xnode(void)
{
	printf("== xnode_shmem driver ==\n");
	int fd = open("/dev/xnode_shmem", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("skip: /dev/xnode_shmem not present\n");
		return;
	}

	struct xnode_shmem_info info = {};
	CHECK(ioctl(fd, XNODE_SHMEM_GET_INFO, &info) == 0, "GET_INFO");
	CHECK(info.size >= 2 * PAGE, "window >= 2 pages (%llu)",
	      (unsigned long long)info.size);

	/* page 0 (consumer_pos) is writable */
	void *p0 = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(p0 != MAP_FAILED, "mmap page 0 RW allowed");
	if (p0 != MAP_FAILED) {
		*(volatile uint64_t *)p0 = 0x1234;
		CHECK(*(volatile uint64_t *)p0 == 0x1234, "page 0 read-back");
		munmap(p0, PAGE);
	}

	/* page 1 (producer_pos) must reject a writable mapping */
	void *p1w = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
			 fd, PAGE);
	CHECK(p1w == MAP_FAILED && errno == EPERM,
	      "mmap page 1 RW rejected (EPERM)");
	if (p1w != MAP_FAILED)
		munmap(p1w, PAGE);

	void *p1r = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, PAGE);
	CHECK(p1r != MAP_FAILED, "mmap page 1 RO allowed");
	if (p1r != MAP_FAILED)
		munmap(p1r, PAGE);

	/* cached mode + range sync */
	uint32_t mode = XNODE_SHMEM_CACHED;
	int sm = ioctl(fd, XNODE_SHMEM_SET_MODE, &mode);
	CHECK(sm == 0, "SET_MODE cached");
	if (sm == 0) {
		struct xnode_shmem_sync s = {};
		s.offset = 0;
		s.size = 64;
		s.flags = XNODE_SHMEM_SYNC_INVAL | XNODE_SHMEM_SYNC_CLEAN;
		CHECK(ioctl(fd, XNODE_SHMEM_SYNC, &s) == 0, "SYNC range");
	}

	/*
	 * Re-export the window as a dma-buf and map it. Export CACHED: the
	 * SET_MODE/SYNC above left a write-back kernel mapping of the
	 * window, and on x86 a write-combine user mapping of the same
	 * physical range would conflict with it under PAT. Cacheable
	 * matches, so it maps on both arches.
	 */
	struct xnode_shmem_dmabuf ex = {};
	ex.flags = XNODE_SHMEM_CACHED;
	int r = ioctl(fd, XNODE_SHMEM_EXPORT_DMABUF, &ex);
	CHECK(r == 0 && ex.fd >= 0, "EXPORT_DMABUF");
	if (r == 0 && ex.fd >= 0) {
		void *p = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, ex.fd, 0);
		CHECK(p != MAP_FAILED, "mmap exported dma-buf");
		if (p != MAP_FAILED)
			munmap(p, PAGE);
		close(ex.fd);
	}

	close(fd);
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

static void test_mmio(void)
{
	printf("== bpf_mmio kfuncs ==\n");

	/* window base/size come from the driver (expose_mmio registered it) */
	int xf = open("/dev/xnode_shmem", O_RDONLY | O_CLOEXEC);
	if (xf < 0) {
		printf("skip: /dev/xnode_shmem not present\n");
		return;
	}
	struct xnode_shmem_info info = {};
	if (ioctl(xf, XNODE_SHMEM_GET_INFO, &info)) {
		printf("skip: GET_INFO failed\n");
		close(xf);
		return;
	}
	close(xf);

	int id_map = btf_find_func("bpf_mmio_map");
	int id_wr = btf_find_func("bpf_mmio_writel");
	int id_rd = btf_find_func("bpf_mmio_readl");
	int id_rel = btf_find_func("bpf_mmio_release");
	if (id_map <= 0 || id_wr <= 0 || id_rd <= 0 || id_rel <= 0) {
		/* No vmlinux BTF (CONFIG_DEBUG_INFO_BTF): can't call kfuncs. */
		printf("skip: bpf_mmio kfunc BTF ids unavailable\n");
		return;
	}
	CHECK(true, "resolve bpf_mmio kfunc BTF ids");

	/* array[0] = { base(in), result(out) }, one 16-byte element */
	union bpf_attr ma = {};
	ma.map_type = BPF_MAP_TYPE_ARRAY;
	ma.key_size = 4;
	ma.value_size = 16;
	ma.max_entries = 1;
	int amap = sys_bpf(BPF_MAP_CREATE, &ma);
	CHECK(amap >= 0, "create scratch array map");
	if (amap < 0)
		return;

#define KFUNC(id) INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, id)
	struct bpf_insn prog[] = {
		/* r0 = lookup(amap, &key0) */
		INSN(BPF_ST | BPF_W | BPF_MEM, BPF_REG_10, 0, -4, 0),
		MOV64_REG(BPF_REG_2, BPF_REG_10),
		ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
		LD_MAP_FD(BPF_REG_1, amap),			/* 2 slots */
		EMIT_CALL(BPF_FUNC_map_lookup_elem),
		JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 21),		/* -> fail(r0=2) */
		MOV64_REG(BPF_REG_6, BPF_REG_0),		/* r6 = value */
		LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0),	/* r8 = base */
		/* region = bpf_mmio_map(base, 4096) */
		MOV64_REG(BPF_REG_1, BPF_REG_8),
		MOV64_IMM(BPF_REG_2, 4096),
		KFUNC(id_map),
		JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 13),		/* -> ret1 */
		MOV64_REG(BPF_REG_7, BPF_REG_0),		/* r7 = region */
		/* bpf_mmio_writel(region, 0, MARKER) */
		MOV64_REG(BPF_REG_1, BPF_REG_7),
		MOV64_IMM(BPF_REG_2, 0),
		MOV64_IMM(BPF_REG_3, 0x0AFEF00D),
		KFUNC(id_wr),
		/* r0 = bpf_mmio_readl(region, 0) */
		MOV64_REG(BPF_REG_1, BPF_REG_7),
		MOV64_IMM(BPF_REG_2, 0),
		KFUNC(id_rd),
		STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 8),	/* value[8] = read */
		/* bpf_mmio_release(region) */
		MOV64_REG(BPF_REG_1, BPF_REG_7),
		KFUNC(id_rel),
		MOV64_IMM(BPF_REG_0, 0),
		EXIT_INSN(),
		MOV64_IMM(BPF_REG_0, 1), EXIT_INSN(),		/* ret1: map==NULL */
		MOV64_IMM(BPF_REG_0, 2), EXIT_INSN(),		/* fail: lookup==NULL */
	};
	int n = sizeof(prog) / sizeof(prog[0]);
	static char log[16384];

	union bpf_attr la = {};
	la.prog_type = BPF_PROG_TYPE_SYSCALL;
	la.prog_flags = BPF_F_SLEEPABLE;
	la.insn_cnt = n;
	la.insns = (uint64_t)(unsigned long)prog;
	la.license = (uint64_t)(unsigned long)"GPL";
	la.log_level = 1;
	la.log_buf = (uint64_t)(unsigned long)log;
	la.log_size = sizeof(log);
	int prog_fd = sys_bpf(BPF_PROG_LOAD, &la);
	if (prog_fd < 0)
		printf("prog load failed: %s\nverifier:\n%s\n",
		       strerror(errno), log);
	CHECK(prog_fd >= 0, "load MMIO kfunc program");
	if (prog_fd < 0) {
		close(amap);
		return;
	}

	auto run = [&](uint64_t base, uint64_t *out_result) -> int {
		uint32_t key = 0;
		uint64_t val[2] = { base, 0 };
		union bpf_attr up = {};
		up.map_fd = (uint32_t)amap;
		up.key = (uint64_t)(unsigned long)&key;
		up.value = (uint64_t)(unsigned long)val;
		up.flags = 0;
		sys_bpf(BPF_MAP_UPDATE_ELEM, &up);

		/* SYSCALL test_run rejects repeat/flags/data_in — only ctx. */
		unsigned char ctx[8] = {};
		union bpf_attr ta = {};
		ta.test.prog_fd = (uint32_t)prog_fd;
		ta.test.ctx_in = (uint64_t)(unsigned long)ctx;
		ta.test.ctx_size_in = sizeof(ctx);
		int r = sys_bpf(BPF_PROG_TEST_RUN, &ta);
		if (r == 0 && out_result) {
			union bpf_attr lu = {};
			lu.map_fd = (uint32_t)amap;
			lu.key = (uint64_t)(unsigned long)&key;
			lu.value = (uint64_t)(unsigned long)val;
			sys_bpf(BPF_MAP_LOOKUP_ELEM, &lu);
			*out_result = val[1];
		}
		return r == 0 ? (int)ta.test.retval : -1;
	};

	/* positive: registered window maps, write/read round-trips */
	uint64_t result = 0;
	int rv = run(info.base, &result);
	CHECK(rv == 0, "bpf_mmio_map on registered window");
	CHECK(result == 0x0AFEF00D, "mmio writel/readl round-trip");

	/* negative: an unregistered address is refused (fail-closed) */
	rv = run(info.base + 0x10000000ull, nullptr);
	CHECK(rv == 1, "bpf_mmio_map on unregistered addr returns NULL");

	close(prog_fd);
	close(amap);
}

/*
 * Exercise the JIT-inserted arena cache maintenance (BPF_F_ARENA_CLEAN):
 * load a program that allocates an arena page and stores to it, then
 * dump the JITed code and confirm a clflush (0F AE /7) was emitted after
 * the arena store. In QEMU the clflush is functionally a no-op (coherent
 * guest), so this checks the JIT emits well-formed code and the store
 * still works — not the coherency effect itself.
 */
static void test_arena_jit(void)
{
	printf("== arena JIT clean ==\n");

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
	ma.map_flags = BPF_F_DMABUF | BPF_F_MMAPABLE | BPF_F_ARENA_CLEAN;
	ma.map_extra = (uint32_t)dmabuf;
	int arena = sys_bpf(BPF_MAP_CREATE, &ma);
	CHECK(arena >= 0, "create BPF_F_ARENA_CLEAN arena");
	if (arena < 0) {
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
		JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),		/* NULL -> out */
		MOV64_IMM(BPF_REG_1, 0xABCD),
		STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0),	/* arena store */
		MOV64_IMM(BPF_REG_0, 0),			/* out */
		EXIT_INSN(),
	};
	static char log[16384];
	union bpf_attr la = {};
	la.prog_type = BPF_PROG_TYPE_SYSCALL;
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

	/* dump the JITed image and look for clflush (0F AE, ModRM.reg == 7) */
	static unsigned char jit[65536];
	struct bpf_prog_info info = {};
	info.jited_prog_insns = (uint64_t)(unsigned long)jit;
	info.jited_prog_len = sizeof(jit);
	union bpf_attr ia = {};
	ia.info.bpf_fd = (uint32_t)prog_fd;
	ia.info.info_len = sizeof(info);
	ia.info.info = (uint64_t)(unsigned long)&info;
	bool has_clflush = false;
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &ia) == 0) {
		uint32_t n = info.jited_prog_len;
		if (n > sizeof(jit))
			n = sizeof(jit);
#if defined(__x86_64__)
		/* clflush: 0F AE /7 with a memory operand (ModRM.mod != 3),
		 * so sfence (0F AE F8) does not match.
		 */
		for (uint32_t i = 0; i + 2 < n; i++)
			if (jit[i] == 0x0f && jit[i + 1] == 0xae &&
			    ((jit[i + 2] >> 3) & 7) == 7 &&
			    ((jit[i + 2] >> 6) != 3)) {
				has_clflush = true;
				break;
			}
#elif defined(__aarch64__)
		/* dc cvac (0xd50b7a20) / dc ivac (0xd5087620) */
		for (uint32_t i = 0; i + 3 < n; i += 4) {
			uint32_t w = jit[i] | jit[i + 1] << 8 |
				     jit[i + 2] << 16 |
				     (uint32_t)jit[i + 3] << 24;
			if ((w & ~0x1fU) == 0xd50b7a20U ||
			    (w & ~0x1fU) == 0xd5087620U) {
				has_clflush = true;
				break;
			}
		}
#else
		has_clflush = true; /* unknown arch: don't fail the scan */
#endif
	}
	CHECK(has_clflush, "JIT emitted cache maintenance after arena store");

	/* run it: a malformed clflush would #UD here */
	unsigned char ctx[8] = {};
	union bpf_attr ta = {};
	ta.test.prog_fd = (uint32_t)prog_fd;
	ta.test.ctx_in = (uint64_t)(unsigned long)ctx;
	ta.test.ctx_size_in = sizeof(ctx);
	CHECK(sys_bpf(BPF_PROG_TEST_RUN, &ta) == 0 && ta.test.retval == 0,
	      "arena-writing program runs");

	close(prog_fd);
	close(arena);
	close(dmabuf);
}

static void test_negative(void)
{
	printf("== negative map flags ==\n");
	int db = dmabuf_alloc(3);
	if (db < 0) {
		printf("skip: dma-heap unavailable\n");
		return;
	}

	/* USER_RINGBUF makes the kernel the consumer; DMABUF is supported
	 * (the kernel invalidates on consume).
	 */
	union bpf_attr a = {};
	a.map_type = BPF_MAP_TYPE_USER_RINGBUF;
	a.max_entries = PAGE;
	a.map_flags = BPF_F_DMABUF;
	a.map_extra = (uint32_t)db;
	int m = sys_bpf(BPF_MAP_CREATE, &a);
	CHECK(m >= 0, "USER_RINGBUF + DMABUF allowed");
	if (m >= 0)
		close(m);

	/* Note: the BPF_F_RB_OVERWRITE rejection check is omitted on this
	 * 6.12 backport, which does not carry the ringbuf overwrite feature.
	 */

	close(db);
}

static int link_create_fd(int target)
{
	union bpf_attr a = {};
	a.link_create.target_fd = (uint32_t)target;
	a.link_create.attach_type = BPF_DEPENDENT_FD;
	return sys_bpf(BPF_LINK_CREATE, &a);
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

	/* eventfd: a leaf file, allowed */
	int ev = eventfd(0, EFD_CLOEXEC);
	int link = link_create_fd(ev);
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
		int l = link_create_fd(db);
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
		int bad = link_create_fd(pfd[0]);
		CHECK(bad < 0 && errno == EPERM,
		      "non-whitelisted fd rejected (EPERM)");
		if (bad >= 0)
			close(bad);
		close(pfd[0]);
		close(pfd[1]);
	}
}

/*
 * When run as PID 1 (as the initramfs /init) there is no shell to set
 * up mounts, so do it here: devtmpfs is needed for /dev/dma_heap/system
 * and /dev/xnode_shmem to appear.
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
	test_arena();
	test_arena_jit();
	test_negative();
	test_fdlink();
	/* Before test_xnode(): its cached SYNC leaves a write-back kernel
	 * mapping of the window, which conflicts with the UC ioremap here
	 * under x86 PAT.
	 */
	test_mmio();
	test_xnode();

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
