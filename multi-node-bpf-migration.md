# Migrating from the multi-node BPF prototype

The original prototype (the 5 `multi-node-bpf` patches) authorized shared
memory by **raw physical address** and had a few unsafe/broken corners.
The current design authorizes by **dma-buf fd** and reworks the ringbuf
layout, arena cache maintenance, MMIO access, and fd links. This is a
breaking change to the UAPI. Below is what to change, by area.

## 1. Map flags: `*_RESERVED` → `BPF_F_DMABUF`

The two per-map flags collapsed into one.

| Prototype | Now |
|-----------|-----|
| `BPF_F_RINGBUF_RESERVED` (bit 20) | `BPF_F_DMABUF` (bit 20) |
| `BPF_F_ARENA_RESERVED` (bit 21)   | `BPF_F_DMABUF` (bit 20) |

```c
/* before */
attr.map_flags = BPF_F_RINGBUF_RESERVED;      /* or BPF_F_ARENA_RESERVED */
/* after */
attr.map_flags = BPF_F_DMABUF;
```

New arena-only flags occupy bits 21/22 (`BPF_F_ARENA_CLEAN`,
`BPF_F_ARENA_INVAL`) — see §4.

## 2. `map_extra`: physical address → dma-buf fd

`map_extra` no longer carries a physical base address. It carries a
**dma-buf fd**. Allocate the buffer from a dma-heap that owns the shared
window (see §2a) and pass its fd.

```c
/* before */
attr.map_extra = 0x8f000000;                  /* physical base */

/* after */
int dmabuf = /* allocate from /dev/dma_heap/<region-node-name> */;
attr.map_extra = dmabuf;                       /* the fd */
```

Requirements now enforced at map creation:

- `CONFIG_DMA_SHARED_BUFFER` must be enabled (`-EOPNOTSUPP` otherwise).
- The arch must have cache maintenance support
  (`-EOPNOTSUPP` otherwise; arm64 and x86-64 today).
- The `CAP_SYS_ADMIN` / raw-`pfn_valid` checks are gone — access is now
  controlled by the exporter's file permissions on the fd. Physically
  contiguous placement is the exporter's responsibility.

The exporter must be **page-backed** for a BPF map to import it: a CMA
dma-heap (§2a) or the system heap. A `no-map` region has no `struct page`s
and cannot back a map.

## 2a. Memory source: per-region CMA dma-heap

Back the window with a **CMA region declared in the device tree**, exposed
as its own dma-heap by the "CMA heap per reserved region" support
(`drivers/dma-buf/heaps/cma_heap.c`; upstream in v6.19, cherry-picked onto
this branch). A `shared-dma-pool reusable` reserved-memory node becomes
`/dev/dma_heap/<node-full-name>`, page-backed:

```dts
reserved-memory {
	#address-cells = <2>;
	#size-cells = <2>;
	ranges;

	agent_win: agent_win@4013000000 {
		compatible = "shared-dma-pool";
		reusable;                             /* -> CMA area -> its own heap */
		reg = <0x40 0x13000000 0x0 0x200000>; /* node-local base, 2 MiB */
	};
};
```
→ `/dev/dma_heap/agent_win@4013000000`, bound to *this* region's CMA area
(named `cma_get_name(cma)` = the node name), **not** the default `reserved`
area. If you see allocations landing on `reserved`, a second heap creator
(e.g. a downstream `dynamic_cma_heap.c`) is fighting this one for the name —
remove it; this series is its replacement.

**Cross-node addressing.** The two nodes see the same RAM at *different*
physical bases (the daemon's interconnect translation), so never share an
absolute address — share the **offset within the region**, and each side
computes `node_base + offset`. Because a dynamic `cma_alloc()` placement is
*unobservable* from userspace, do not sub-allocate a slice and expect the
peer to find it. Instead:

- **one region per buffer** (declare each shared buffer as its own
  reserved-memory node → its own heap; each side knows the base from its
  DT, allocate the whole region on both sides — deterministic, no
  discovery); or
- **allocate the whole region once** and partition it by agreed offsets in
  software on both sides.

**`reusable` caveat.** A CMA region is used by the page allocator as
movable fallback, so on a memory-constrained node its pages get pinned and
`cma_alloc()` can fail with `-EBUSY` even with free bytes left (migration
of a pinned page fails — it is not an out-of-memory error). Mitigate by
sizing the region to exactly the window and allocating it **once, as early
in boot as possible**, before pressure fills the pool, then holding it for
the deployment lifetime. This is a mitigation, not a guarantee; the only
way to remove the failure mode entirely is an exclusive (non-`reusable`)
reservation, which mainline has no dma-heap for.

## 3. Ringbuf: window layout changed

The prototype placed the entire `struct bpf_ringbuf`, including its
kernel-private part, in the reserved region — so a remote consumer read
kernel pointers and had to skip `RINGBUF_PGOFF` pages to reach
`consumer_pos`. Now the kernel-private state stays in normal memory and
**only the position/data pages come from the dma-buf**:

| dma-buf offset | contents       |
|----------------|----------------|
| page 0         | `consumer_pos` |
| page 1         | `producer_pos` |
| page 2+        | data (records) |

A remote consumer must update its offsets:

```c
/* before: relative to the physical base */
consumer_pos = base + RINGBUF_PGOFF * PAGE;

/* after: relative to the dma-buf */
consumer_pos = dmabuf_map + 0;
producer_pos = dmabuf_map + PAGE;
data         = dmabuf_map + 2 * PAGE;
```

Other ringbuf changes:

- `BPF_MAP_TYPE_USER_RINGBUF + BPF_F_DMABUF` is now **supported** (kernel
  consumer; it invalidates on `bpf_user_ringbuf_drain`). The prototype
  had no such path.
- `BPF_F_RB_OVERWRITE + BPF_F_DMABUF` is **rejected** (`-EINVAL`) — the
  overwrite position is not part of the maintenance protocol.
- Cache maintenance on the kernel producer path is automatic; the consumer
  side depends on your interconnect's coherency — see §3a.

## 3a. Cache maintenance by interconnect coherency

The ring buffer crosses the boundary in two directions:

- **producer → consumer**: the producer writes records and `producer_pos`,
  the consumer reads them.
- **consumer → producer**: the consumer writes `consumer_pos`, the producer
  reads it.

For a write to cross a **non-coherent** direction it needs *two* things:
the **writer** pushes the value to the shared DRAM — a **clean** (`DC CVAC`)
or a write-combine/uncached mapping — and the **reader** drops any stale
copy — an **invalidate** (`DC IVAC`) — before reading. A **coherent**
direction removes the reader's invalidate; if it is *fully* cache-coherent
(reader snoops the writer's cache) it removes the writer's clean too, but a
common weaker form — "writes are pushed to the peer once they reach DRAM"
(a common hardware guarantee) — still requires the writer's clean.

Which op runs where matters for *where the code can live*: **`DC CVAC`
(clean) is EL0-legal**, so a cleaning side can be plain userspace;
**`DC IVAC` (invalidate) is EL1-only**, so an invalidating side must run in
the kernel (JIT / `bpf_user_ringbuf_drain`) or behind a driver.

The four configurations (`clean` = writer→DRAM, `inval` = reader drops
stale; `—` = nothing):

### 1. Fully coherent both ways

| path | producer | consumer |
|------|----------|----------|
| data / `producer_pos` | — | — |
| `consumer_pos`        | — | — |

No cache maintenance at all — just `acquire`/`release` ordering, like a
same-machine ring buffer.

### 2. Producer coherent with consumer (P→C only)

| path | producer | consumer |
|------|----------|----------|
| data / `producer_pos` | clean\* | **—** |
| `consumer_pos`        | inval  | clean (or WC page 0) |

\* Still required under the "pushed-from-DRAM" form; a *fully* cache-coherent
P→C would drop it too. The consumer needs **no invalidate**, so it can be
**plain userspace**: read cacheable (fresh via the push) and publish
`consumer_pos` with a `DC CVAC` or a write-combine page-0 mapping. This is
the typical asymmetric-coherency case.

### 3. Consumer coherent with producer (C→P only)

| path | producer | consumer |
|------|----------|----------|
| data / `producer_pos` | clean | inval |
| `consumer_pos`        | —     | clean\* |

The consumer must **invalidate** to see producer data → it must run **in
the kernel** (`USER_RINGBUF` drain / arena `INVAL`); a userspace reader
can't (`DC IVAC` is privileged).

### 4. No coherency either way

| path | producer | consumer |
|------|----------|----------|
| data / `producer_pos` | clean | inval |
| `consumer_pos`        | inval | clean |

Full maintenance on both paths; the consumer invalidates, so again it runs
in the kernel.

### What the code already does

The kernel producer path (`bpf_ringbuf_reserve`/`commit`) **cleans**
records/header/`producer_pos` and **invalidates** `consumer_pos` before
reading it — the correct, safe superset for cases 2–4 (a redundant clean in
a coherent direction is harmless). Pick the consumer accordingly: a
**userspace** reader is valid only when the consumer needs no invalidate
(case 2 — see §6), otherwise use the in-kernel `bpf_user_ringbuf_drain`
(cases 3–4), which invalidates `producer_pos`/header/record and cleans
`consumer_pos` and so is safe for cases 2–4 as well.

## 4. Arena: no maintenance was done; now use the flags

The prototype's `BPF_F_ARENA_RESERVED` did **no** cache maintenance, so a
producer's writes were never guaranteed to reach the non-coherent
reader. Fix by adding, alongside `BPF_F_DMABUF`:

- `BPF_F_ARENA_CLEAN` — the JIT emits a clean (write-back) after each
  arena store, for a producer.
- `BPF_F_ARENA_INVAL` — the JIT emits an invalidate before each arena
  load, for an in-BPF consumer.

```c
attr.map_flags = BPF_F_DMABUF | BPF_F_MMAPABLE | BPF_F_ARENA_CLEAN;
```

No program change and no kfunc call — the maintenance is inserted by the
JIT around the program's own arena accesses. (An interim
`bpf_arena_cache_clean()` kfunc that briefly existed on this branch has
been removed; delete any calls to it.) The clean/invalidate carry no
ordering — use `store_release`/`load_acquire` at the producer/consumer
handoff.

Two behaviours to be aware of:

- `bpf_arena_alloc_pages()`/`bpf_arena_free_pages()` now work on dma-buf
  arenas (range-tree bookkeeping over the pre-mapped window); the
  prototype disabled them. **Allocated ranges are not zeroed.**
- The verifier requires an arena's `user_vm_start` to be set before a
  program can reference it. A dma-buf arena's `map_extra` is the fd, so
  **`mmap()` the arena (4 GiB-aligned) before loading** the program:

  ```c
  mmap((void *)0x4000000000ULL, size, PROT_READ | PROT_WRITE,
       MAP_SHARED | MAP_FIXED, arena_fd, 0);   /* then load */
  ```

## 5. MMIO kfuncs: two ways to name an aperture

There are two ways to obtain a `struct bpf_mmio_region *`; pick per aperture.
Everything downstream — the `bpf_mmio_readl`/`writel`/… accessors,
`bpf_mmio_release`, and the kptr/destructor — is identical, and both map
kfuncs are `KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE`.

**(a) `bpf_mmio_map_region(phys, size)` — driver-allowlisted physical range.**
For a *fixed* aperture owned by a trusted in-kernel driver (a doorbell /
mailbox). The driver blesses the range; access is gated by that registration
plus `CAP_BPF`. Takes **no fd**, so it can be mapped from any process context.

```c
/* driver that owns the aperture */
bpf_mmio_register_region(doorbell_phys, size);   /* ... unregister at exit */

/* BPF: map once (any context — no fget) and stash the kptr */
r = bpf_mmio_map_region(DOORBELL_PHYS, size);
```
Fail-closed: with nothing registered, `bpf_mmio_map_region()` returns NULL.

**(b) `bpf_mmio_map(fd, offset, size)` — fd-scoped via a provider.** For an
aperture whose access should follow *fd/process ownership* (e.g. a vfio-pci
BAR handed to a specific process). A provider registers its fd's
`file_operations` + a resolver via `bpf_mmio_register_provider()`;
`bpf_mmio_map()` `fget()`s the fd, so the map call **must run in the process
holding the fd**. With no provider registered it fails for every fd.

```c
r = bpf_mmio_map(bar_fd, offset, size);   /* fd from the provider */
```

Which to use: a fixed doorbell your own driver owns → (a); a per-process
device handoff → (b).

### Usage pattern (both): map once, stash a kptr, use later

`ioremap()` is sleepable, so you don't map per event — map once in a
sleepable context, stash the acquired region as a
`struct bpf_mmio_region __kptr *`, and read it from the fast path (e.g. an
LSM hook). For path (b) the setup program must run in the fd holder's
process; for path (a) any context works.

```c
struct { struct bpf_mmio_region __kptr *region; } val;   /* in a map / global */

SEC("syscall")                           /* run once via bpf_prog_test_run */
int setup(void *ctx)
{
	struct bpf_mmio_region *r = bpf_mmio_map_region(DOORBELL_PHYS, 0x1000);
	if (!r)
		return 1;
	r = bpf_kptr_xchg(&val.region, r);   /* stash; returns previous (NULL) */
	if (r)
		bpf_mmio_release(r);
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(on_exec, struct linux_binprm *bprm)
{
	/* A *referenced* kptr read is untrusted, and bpf_mmio_writel is KF_RCU,
	 * so a direct `r = val.region` is rejected ("R1 must be a rcu pointer").
	 * Take the region out with an atomic xchg (an owned, trusted ref the
	 * accessor accepts), use it, and put it back.
	 */
	struct bpf_mmio_region *r = bpf_kptr_xchg(&val.region, NULL);
	if (!r)                                    /* setup hasn't run yet */
		return 0;
	bpf_mmio_writel(r, DOORBELL_OFF, value);
	r = bpf_kptr_xchg(&val.region, r);         /* put it back */
	if (r)
		bpf_mmio_release(r);
	return 0;
}
```

The kptr's destructor `iounmap()`s (and `fput()`s the fd, for path (b)) when
it is replaced or the map is freed.

Notes:

- The mmio kfunc set is registered for tracing, sched_cls, xdp, struct_ops,
  **syscall**, and **lsm** program types — so both the `SEC("syscall")` setup
  and the `SEC("lsm/…")` hook can call it.
- **Referenced-kptr access.** `bpf_mmio_writel` is `KF_RCU`, and a referenced
  kptr read is *untrusted* even inside `bpf_rcu_read_lock()` (the region is
  not a registered RCU-safe type). Use `bpf_kptr_xchg()` out/in as above; note
  it is atomic, so concurrent hook invocations serialize and a contended one
  sees NULL (fine for a doorbell — one poke wins). If you need concurrent
  lock-free reads, the region type would have to be made an RCU-safe kptr.
- **BPF-LSM attach needs the trampoline.** LSM programs attach via an fentry
  trampoline, which requires `CONFIG_FUNCTION_TRACER` /
  `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS`; without them attach fails with
  `-EBUSY`. Prefer an *int*-returning hook such as `bprm_check_security` —
  the `void` `bprm_committed_creds` is harder to attach a program to.
- `bpf_mmio_readq`/`writeq` are 64-bit only.

## 6. Consumer node: prefer a driverless in-BPF consumer

The reading node must stop mapping the window through raw `/dev/mem`. The
**recommended** consumer is driverless and needs no `xnode_shmem`:

- Declare the same window on the consumer as its own CMA region (§2a) at
  the consumer node's physical base (daemon-injected) and allocate a
  page-backed dma-buf from `/dev/dma_heap/<node-name>`.
- Run the consumer **in BPF**: a `BPF_MAP_TYPE_USER_RINGBUF + BPF_F_DMABUF`
  map drained with `bpf_user_ringbuf_drain()` (§3), or a `BPF_F_ARENA_INVAL`
  arena for free-form data. The drain/arena path issues the invalidate
  (`DC IVAC`) in **kernel context**, so it works on arm64 where EL0 cannot
  — which is why no driver is needed.

`xnode_shmem` is only for cases the in-BPF consumer doesn't cover: a
**userspace** consumer that must `mmap` the window write-combine, or a
**cached** userspace consumer that needs the privileged `DC IVAC` via a
range-sync ioctl, plus the page-0-only-writable discipline.
`drivers/misc/xnode_shmem.c` provides that, **but it is a reference driver,
not for upstream as-is** — fold its interface (`GET_INFO`, mmap discipline,
`SET_MODE`/`SYNC`) into the device driver that owns the window. When the
producer is coherent with the consumer (§3a case 2), a driverless
*userspace* consumer — no BPF map, no `xnode_shmem` — is also possible; see
§6a.

## 6a. Userspace consumer when the producer is coherent with the consumer

When the interconnect keeps the consumer coherent for producer writes
(§3a case 2), the consumer needs **no invalidate** — only a way to publish
`consumer_pos` back to DRAM. That removes the EL1-only `DC IVAC`, so the
consumer can be **plain userspace**, with no BPF map and no driver:

- **Do not create a BPF ring buffer map on the consumer.** Both `RINGBUF`
  and `USER_RINGBUF` creation re-initialize `producer_pos`/`consumer_pos`
  to zero, which would stomp the producer's shared state. The consumer just
  maps the raw window and reads/writes the bytes.
- Map the data/`producer_pos` pages **cacheable** (reads are fresh via the
  producer→consumer push) and page 0 (`consumer_pos`) **write-combine**, so
  the `consumer_pos` store reaches DRAM with only a `DSB` — no `DC CVAC`.
  (Alternatively map everything cacheable and `DC CVAC` `consumer_pos` after
  each update; `DC CVAC` is EL0-legal.)

```c
/* window mapped from the consumer's own CMA dma-heap region (§2a);
 * page 0 write-combine, the rest cacheable.
 */
volatile __u64 *cons = win;                 /* consumer_pos (WC)   */
volatile __u64 *prod = win + PAGE;          /* producer_pos (cach) */
__u8           *data = win + 2 * PAGE;
__u64 mask = DATA_SIZE - 1;                 /* DATA_SIZE = pow2     */

for (;;) {
	__u64 cp = *cons;
	__u64 pp = __atomic_load_n(prod, __ATOMIC_ACQUIRE);  /* fresh: pushed */
	while (cp < pp) {
		__u32 *hdr = (void *)(data + (cp & mask));
		__u32 len  = __atomic_load_n(hdr, __ATOMIC_ACQUIRE);
		if (len & (1u << 31))              /* BUSY: still being written */
			break;
		__u32 sz    = len & ~(3u << 30);   /* strip BUSY|DISCARD        */
		__u32 total = (sz + 8 + 7) & ~7u;
		if (!(len & (1u << 30)))           /* not DISCARD               */
			handle(hdr + 2, sz);       /* payload; cacheable = fresh */
		cp += total;
		*cons = cp;                        /* WC store -> DRAM          */
		asm volatile("dsb sy" ::: "memory");
	}
	wait_doorbell();                           /* eventfd / mailbox       */
}
```

Notes:

- A record can wrap the end of the data region. Either double-map the data
  pages (`mmap` the dma-buf's data range twice, contiguous, so a wrapped
  record reads linearly — what the kernel side does) or handle the split in
  `handle()`.
- The `DSB` after the `consumer_pos` store ensures it has drained to DRAM
  before you block/return, so the producer's invalidate-then-read sees it.
- This is only valid for §3a case 2. If the consumer must invalidate
  (cases 3–4), it cannot run in userspace on arm64 — use the in-BPF drain
  (§6).

### Using libbpf instead of hand-rolling it

libbpf can do the walk above for you — including the wrap-around
double-mapping and the poll integration — via **`ring_buffer__add_dmabuf()`**
(added alongside this series). It consumes a dma-buf backed ring buffer
whose *map fd is not available* (the peer maps the shared dma-buf but did
not create the map), so you don't reimplement the record loop:

```c
/* empty manager: pass map_fd < 0 (there is no ring buffer map here) */
struct ring_buffer *rb = ring_buffer__new(-1, NULL, NULL, NULL);

/* dmabuf_fd: the shared window's dma-buf; data_size: the ring's max_entries
 * (power of two, page-aligned); notify_fd: your doorbell eventfd or -1.
 */
ring_buffer__add_dmabuf(rb, dmabuf_fd, data_size, notify_fd, on_sample, ctx);

ring_buffer__poll(rb, -1);      /* waits on notify_fd, then drains  */
/* or ring_buffer__consume(rb) after your own doorbell wakeup       */
```

`ring_buffer__add_dmabuf()` mmaps the dma-buf (consumer page + a
double-mapped producer/data region) and reuses libbpf's record walk;
`on_sample(ctx, data, size)` is called per record.

**Coherency stays yours.** libbpf only walks the records — it issues no
cache maintenance. That is correct for §3a case 2 (producer coherent with
the consumer: cacheable reads are fresh, and you map `consumer_pos`
write-combine so its store reaches DRAM). It is *not* sufficient for cases
3–4, which need an invalidate the library does not (and, being EL1-only,
cannot) do — use the in-BPF drain (§6) there. See
`ring_buffer__add_dmabuf()` in `tools/lib/bpf/libbpf.h` for the contract.

## 7. fd links: only leaf file types

`BPF_LINK_TYPE_FD` (`attach_type BPF_DEPENDENT_FD`) now accepts only
**eventfd** and **dma-buf** fds; pinning any other fd type returns
`-EPERM` (reference-cycle safety). If you pinned other fd types, that no
longer works. Link info now reports the kind/inode
(`bpf_link_info.fd`).

## Quick checklist

- [ ] Replace `BPF_F_{RINGBUF,ARENA}_RESERVED` with `BPF_F_DMABUF`.
- [ ] Declare the window as a `shared-dma-pool reusable` region → allocate
      its page-backed dma-buf from `/dev/dma_heap/<node-name>` (§2a); put
      the fd in `map_extra`. One region per shared buffer; allocate early
      and hold to dodge `-EBUSY`.
- [ ] Share **offsets**, not physical addresses, between nodes (§2a).
- [ ] Recompute the remote ringbuf consumer's offsets (page 0 =
      `consumer_pos`).
- [ ] Add `BPF_F_ARENA_CLEAN`/`INVAL` to arena maps; drop any
      `bpf_arena_cache_clean()` calls; `mmap()` the arena before load.
- [ ] MMIO: for a driver-owned fixed aperture, `bpf_mmio_register_region()`
      + `bpf_mmio_map_region(phys,size)`; for a per-process aperture,
      `bpf_mmio_register_provider()` + `bpf_mmio_map(fd,offset,size)`. Map
      once, stash a `bpf_mmio_region __kptr`, use from the hook (§5).
- [ ] Consumer node: move off `/dev/mem` to a driverless in-BPF consumer
      (`USER_RINGBUF`/arena `INVAL`); keep `xnode_shmem` only for a
      userspace/cached consumer.
- [ ] Ensure any pinned fd links are eventfd or dma-buf only.
