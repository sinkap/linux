# Migrating from the multi-node BPF prototype

The original prototype (the 5 `multi-node-bpf` patches) authorized shared
memory by **raw physical address** and had a few unsafe/broken corners.
The current design authorizes by **dma-buf fd**: one dma-buf backs one
arena, ring buffers *and* arrays are placed inside it, there is **no**
in-kernel cache maintenance, and MMIO access and fd links are reworked.
This is a breaking change to the UAPI. Below is what to change, by area.

## 1. Map flags: one dma-buf arena backs everything

The old model gave every shared map its own flag and its own dma-buf.
Now **one dma-buf backs one arena**, and other maps are *placed inside
that arena*:

| Before | Now |
|-----------|-----|
| `BPF_F_RINGBUF_RESERVED` / ringbuf + `BPF_F_DMABUF` | ringbuf + `BPF_F_ARENA_BACKED` (bit 20), placed in an arena |
| raw arena pointers for shared state | array + `BPF_F_ARENA_BACKED` (+ `BPF_F_MMAPABLE`), placed in the arena (§3b) |
| `BPF_F_ARENA_RESERVED` (arena on the window) | arena + `BPF_F_DMABUF` (bit 21) |

`BPF_F_ARENA_BACKED` is generic — a ring buffer *or* an array (`BPF_MAP_TYPE_
ARRAY`) can be placed inside one arena, and several maps of mixed types
coexist in one window at distinct, kernel-chosen offsets.

```c
/* the one shared window: an arena backed by the dma-buf */
arena_attr.map_flags = BPF_F_MMAPABLE | BPF_F_DMABUF;
arena_attr.map_extra = dmabuf_fd;

/* a ring buffer lives inside the arena */
rb_attr.map_flags = BPF_F_ARENA_BACKED;
rb_attr.map_extra = arena_fd;

/* so does an array (shared state); mmap the array fd for local access */
arr_attr.map_flags = BPF_F_ARENA_BACKED | BPF_F_MMAPABLE;
arr_attr.map_extra = arena_fd;
```

The JIT cache-maintenance flags of the previous backport
(`BPF_F_ARENA_CLEAN`/`BPF_F_ARENA_INVAL`) are **gone**: the producers are
fabric-coherent toward the consumer and the reverse direction is
synchronized out of band (your `dma_sync` ioctl), so the kernel performs
no cache maintenance. See §3a.

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
- The `CAP_SYS_ADMIN` / raw-`pfn_valid` checks are gone — access is now
  controlled by the exporter's file permissions on the fd. Physically
  contiguous placement is the exporter's responsibility.

The exporter must be **page-backed** for a BPF map to import it: the
carveout dma-heap, a CMA dma-heap (§2a), or the system heap. A `no-map`
region has no `struct page`s and cannot back a map.

## 2a. Memory source: the carveout dma-heap (recommended)

Back the window with an **exclusive reserved-memory carveout**, exposed as
its own dma-heap by the **carveout heap**
(`drivers/dma-buf/heaps/carveout_heap.c`, proposed for upstream). A plain `/reserved-memory` node
that opts in with an `export;` boolean — neither `reusable`/CMA nor
`no-map` — becomes `/dev/dma_heap/<node-full-name>`, page-backed and owned
exclusively by the heap:

```dts
reserved-memory {
	#address-cells = <2>;
	#size-cells = <2>;
	ranges;

	agent_win: agent_win@4013000000 {
		export;                               /* -> carveout dma-heap */
		reg = <0x40 0x13000000 0x0 0x200000>; /* node-local base, 2 MiB */
	};
};
```
→ `/dev/dma_heap/agent_win@4013000000`. Because the region is **exclusive**
(the page allocator never uses it), it has **none** of CMA's failure modes:
no `-EBUSY` under memory pressure, and **no zero-on-allocation** (so a peer
that maps the window first is not wiped). This is why it is the recommended
source for a memory-constrained node.

**Cross-node addressing.** The two nodes see the same RAM at *different*
physical bases (the daemon's interconnect translation), so never share an
absolute address — share the **offset within the region**, and each side
computes `node_base + offset`. Declare **one region per window** (each side
knows the base from its DT and opens the whole region — deterministic, no
discovery); place the arena over it, and let the kernel's arena allocator
partition it into maps at offsets it reports via `arena_off` (§3).

**Alternative: per-region CMA dma-heap.** If you cannot add the carveout
heap, a `shared-dma-pool reusable` reserved-memory node exposed by the
upstream "CMA heap per reserved region" support
(`drivers/dma-buf/heaps/cma_heap.c`, in v6.19) also works
(`/dev/dma_heap/<node-full-name>`, bound to that region's CMA area). But a
CMA region is movable-fallback for the page allocator, so on a constrained
node its pages get pinned and `cma_alloc()` can fail with `-EBUSY` even with
free bytes left (a pinned-page migration failure, not OOM), **and CMA zeroes
on allocation**. Mitigate by sizing the region to exactly the window and
allocating **once, as early in boot as possible**, then holding it — a
mitigation, not a guarantee. The carveout heap removes the failure mode
entirely, which is why it is preferred.

## 3. Ringbuf: placed in the arena, discovered via `arena_off`

A ring buffer no longer imports its own dma-buf. Create it with
`BPF_F_ARENA_BACKED` and the **arena fd** in `map_extra`; the kernel
reserves a sub-region of the arena (its `range_tree` picks the placement)
and reports the byte offset back:

```c
struct bpf_map_info info; __u32 len = sizeof(info);
bpf_map_get_info_by_fd(rb_fd, &info, &len);
/* info.arena_id  == the arena's map id
 * info.arena_off == byte offset of this ring buffer within the arena
 *                   (== within the dma-buf)                          */
```

Publish `arena_off` to the consumer exactly like you already publish
carveout offsets/IOVAs — it slots into the existing discovery mechanism.
From `arena_off` the layout is unchanged:

| dma-buf offset       | contents       |
|----------------------|----------------|
| arena_off + page 0   | `consumer_pos` |
| arena_off + page 1   | `producer_pos` |
| arena_off + page 2+  | data (records) |

The kernel-private ring buffer state stays in normal kernel memory; only
the position/data pages come from the arena. Because the arena maps the
producer page writable to local userspace, the kernel keeps its
`pending_pos` bookkeeping in a private field — nothing you need to do,
but the shared producer page is no longer trusted by the kernel.

Other ringbuf notes:

- `BPF_MAP_TYPE_USER_RINGBUF + BPF_F_ARENA_BACKED` is supported (kernel
  consumer via `bpf_user_ringbuf_drain`).
- `BPF_F_RB_OVERWRITE + BPF_F_ARENA_BACKED` is **rejected** (`-EINVAL`) —
  overwrite mode keeps extra producer state in the shared page.
- The ring buffer's pages are borrowed from the arena for the map's
  lifetime; freeing the ring buffer returns the range to the arena's
  allocator (contents are preserved, ranges are not zeroed).

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

### What the code does now

**Nothing, by design.** This branch carries no in-kernel cache
maintenance: the deployment's producers are one-shot fabric-coherent
toward the consumer (case 2), and the consumer→producer direction
(`consumer_pos`) is synchronized out of band via the `dma_sync` ioctl.
If a future deployment hits cases 3–4 without an out-of-band path, the
maintenance layer can be reintroduced then.

## 3b. Arrays: shared state placed in the arena

For structured shared state that is read/written by both sides — policy,
config, per-flow verdicts, counters, handshake state — use a
`BPF_MAP_TYPE_ARRAY` placed in the same arena (`BPF_F_ARENA_BACKED`,
`map_extra` = the arena fd). Add `BPF_F_MMAPABLE` so local user space can
map it. The kernel reserves the value region in the arena and reports the
placement the same way as the ring buffer:

```c
arr_attr.map_flags = BPF_F_ARENA_BACKED | BPF_F_MMAPABLE;
arr_attr.map_extra = arena_fd;
/* ... bpf_map_get_info_by_fd(arr_fd, &info, ...) -> info.arena_off */
```

Two views of the same value bytes, both live at once:

- **Local** — `mmap()` the array fd and read `value[i]` at offset
  `i * round_up(value_size, 8)`, **from 0**. The arena offset is hidden;
  this is how the agent (or a producer's local user space) touches its own
  arrays.
- **Peer** — a node that only shares the dma-buf reads `value[i]` at
  `arena_off + i * elem_size`. Same physical pages, so the two views are
  coherent under the §3a model.

Only `BPF_MAP_TYPE_ARRAY` is supported (not per-cpu — its storage is a set
of per-cpu allocations, not one contiguous shareable region; not an inner
map). The value region is zeroed on create; a freed-then-reallocated arena
range is not.

One arena hosts a **mix** of maps — several ring buffers and arrays — each
at a distinct, non-overlapping offset the allocator picks and reports. This
is the shape of a real window: streams *and* shared state in one dma-buf.

## 4. Arena: the shared window *and* the allocator

The dma-buf backed arena is now the single owner of the shared window:
BPF programs and local userspace share state through it directly, and
other maps (ring buffers, §3, and arrays, §3b) are carved out of it by the
kernel.

- `bpf_arena_alloc_pages()`/`bpf_arena_free_pages()` on a dma-buf arena
  are pure range-tree bookkeeping over the pre-mapped window. **Allocated
  ranges are not zeroed** — their contents are whatever the window last
  held. Programs with a fixed layout can `bpf_arena_reserve_pages()`
  their regions to keep the allocator (and arena-backed maps) away.
- Local userspace can `mmap()` the arena; the kernel forces a 4 GiB
  aligned address so the lower 32 bits of a pointer equal the offset in
  the window, and page faults resolve to the dma-buf's pages:

  ```c
  void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    arena_fd, 0);   /* kernel picks a 4G-aligned base */
  ```

- The verifier requires an arena's user address range before a program
  referencing it can be loaded; libbpf `mmap()`s the arena during load
  (it knows a dma-buf arena's `map_extra` is an fd, not an address), so
  skeleton users need no extra step.

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
**recommended** consumer is driverless:

- Declare the same window on the consumer as its own CMA region (§2a) at
  the consumer node's physical base (daemon-injected) and allocate a
  page-backed dma-buf from `/dev/dma_heap/<node-name>`.
- Run the consumer **in BPF**: a `BPF_MAP_TYPE_USER_RINGBUF +
  BPF_F_ARENA_BACKED` map (placed in the shared arena) drained with
  `bpf_user_ringbuf_drain()` (§3), or read the arena directly for
  free-form data. With a producer that is fabric-coherent toward this
  node (§3a case 2) no invalidate is needed; if your topology ever needs
  one, that is the point to reintroduce the maintenance layer.

With a producer that is coherent toward the consumer (§3a case 2), a
driverless *userspace* consumer — no BPF map, no window driver — is the
simplest option; see §6a. (This branch carries no window driver: mmap
discipline and any cache synchronization are owned by the device driver
that owns the window, e.g. via its dma_sync ioctl.)

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
/* arena_off: where the kernel placed this ring buffer inside the
 * window (bpf_map_info.arena_off, published by the producer node);
 * 0 for a bare dma-buf ring buffer. */
ring_buffer__add_dmabuf(rb, dmabuf_fd, arena_off, data_size, notify_fd,
			on_sample, ctx);

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

- [ ] One window = one dma-buf = one arena (`BPF_F_DMABUF`,
      `map_extra` = dma-buf fd). Allocate the dma-buf from the **carveout
      heap** (`export;`, exclusive — no `-EBUSY`, no zero-on-alloc); per-
      region CMA is the fallback (§2a).
- [ ] Each shared ring buffer: `BPF_F_ARENA_BACKED`, `map_extra` = arena
      fd; read `bpf_map_info.arena_off` and publish it the way you already
      publish carveout offsets (§3).
- [ ] Shared state: `BPF_MAP_TYPE_ARRAY` + `BPF_F_ARENA_BACKED`
      (+ `BPF_F_MMAPABLE`) in the same arena; local `mmap` reads from 0,
      the peer reads at `arena_off + i*elem_size` (§3b).
- [ ] Share **offsets**, not physical addresses, between nodes (§2a).
- [ ] Drop `BPF_F_ARENA_CLEAN`/`INVAL` and any `bpf_arena_cache_clean()`
      calls — this branch does no in-kernel cache maintenance (§3a);
      coherency is the fabric + your `dma_sync` ioctl.
- [ ] Consumer: `ring_buffer__add_dmabuf(rb, dmabuf_fd, arena_off, ...)`
      (§6a), or the in-BPF consumer (§6).
- [ ] MMIO: for a driver-owned fixed aperture, `bpf_mmio_register_region()`
      + `bpf_mmio_map_region(phys,size)`; for a per-process aperture,
      `bpf_mmio_register_provider()` + `bpf_mmio_map(fd,offset,size)`. Map
      once, stash a `bpf_mmio_region __kptr`, use from the hook (§5).
- [ ] Ensure any pinned fd links are eventfd or dma-buf only (§7).
