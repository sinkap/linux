# Migrating from the multi-node BPF prototype

The original prototype (the 5 `multi-node-bpf` patches) authorized shared
memory by **raw physical address** and had a few unsafe/broken corners.
The current design authorizes by **dma-buf fd**: one dma-buf backs one
arena, ring buffers *and* arrays are placed inside it, there is **no**
in-kernel cache maintenance, wakeups ride a ring buffer **notify_fd**
eventfd instead of MMIO kfuncs, and fd links are reworked.
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

## 2b. Memory source without a device tree (x86, VMs)

x86 has no `/reserved-memory` device tree, so the DT path above does not
apply. Use the arch-generic **`reserve_mem=`** kernel command line, which
reserves RAM early and keeps its struct pages (the same page-backed shape a
DT reserved-memory node without `no-map` has). Opt in by naming the region:

```
reserve_mem=2M:2M:agent_win  carveout_heap.export=agent_win
```
→ `/dev/dma_heap/agent_win`. The DT walk no-ops cleanly when there is no
device tree, so the same driver serves both.

**Dev / test VMs.** Back the *whole* guest RAM with one `share=on`
`memory-backend-file` so the host can map the carveout's bytes; the guest
publishes the reserved guest-physical base and the host maps the matching
offset. Simple, but only acceptable where sharing/pinning all of VM RAM is
fine.

**Production VMs — a second small shared zone (`mem1`).** Do **not** back
all of VM RAM with a shared memfd (it breaks overcommit/isolation for a
tiny window). Instead map a small `share=on` `memory-backend-file` region
(`mem1`, ≈512 KiB–2 MiB) as guest RAM, placed **in `mem0`'s last section**
and the same `guest_numa_id=0`; `mem0` (bulk VM RAM) stays private,
demand-paged, overcommitted. `mem1`'s backing is **not** a private
per-window memfd — it is a **slice, at a per-VM `file_offset`, of one shared
region memfd** (host slot + all VMs' slices) that the host binds and
IOMMU-maps **once** for every VM. The `file_offset` is a host coordinate;
the guest only sees its guest-physical base. Reserve the window at a
**fixed guest-physical base** the VMM chose:

```
reserve_mem=2M:2M:agent_win@0x<base>  carveout_heap.export=agent_win
```
The `@<base>` form reserves at exactly that address or fails — never
relocating. On x86 it is honoured **early in `setup_arch()`, before
`init_mem_mapping()`**, so a top-of-RAM base survives the kernel's own
top-down page-table allocations (a naive top-of-RAM `reserve_mem` fails
without this). Because the VMM placed the backing, the host already knows
where the window is: **no guest→host GPA-publish handshake**, and no
dynamic-placement nondeterminism. Placement rule: put `mem1` in `mem0`'s
**last section** (not merely adjacent) so no new SPARSEMEM `memmap` PMD is
created — otherwise you pay one 2 MiB vmemmap chunk. See the design doc §12
for the full VM deployment (including the
`notify_fd` → host-doorbell wiring). §2c is a simpler alternative that skips
the shared-zone placement rules entirely.

## 2c. Memory source in a VM: virtio-pmem → devdax → `device_dax` exporter

Instead of a shared RAM zone (§2b), let the VMM hand the guest a host-file-backed
**virtio-pmem** device and back the arena with **device pages**. This drops the
`reserve_mem=@base` / `mem1` section-placement gymnastics — the VMM owns
placement by construction — at the cost of a devdax `ndctl` step and device-page
semantics (handled by the arena's `vmf_insert_mixed()` fault path; ordinary-RAM
arenas are unchanged).

```
# host (Cloud Hypervisor): a share=on file becomes the guest's pmem window
cloud-hypervisor --pmem file=/dev/shm/agent_win ... --kernel vmlinux ...

# guest: pmem -> devdax -> dma-buf -> arena
ndctl create-namespace -m devdax --map=mem -f -e namespace0.0   # /dev/dax0.0
int dax    = open("/dev/dax0.0", O_RDWR);
int dmabuf = ioctl(dax, DAX_IOC_EXPORT_DMABUF);   /* device_dax exporter */
attr.map_extra = dmabuf;                          /* BPF_F_DMABUF arena */
```

The guest's BPF writes through the arena land in the host file; the host/NIC
reads the same bytes. **Caveat:** `ndctl` writes a devdax **info block** at the
start of the region, so the usable window begins **2 MiB into the backing file**
(`--map=mem` keeps the page-struct array in guest RAM, not in the window). The
VMM/consumer must offset its view of the file past the info block. Requires the
`DAX_IOC_EXPORT_DMABUF` patch (`drivers/dax/device.c`,
`feature/bpf-next/dax_dmabuf_export`) and, in the guest config, `VIRTIO_PMEM`,
`DEV_DAX`/`DEV_DAX_PMEM`, `FS_DAX`, `ND_PFN`. No `carveout_heap`, no
`reserve_mem`.

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

## 5. Wakeups: the ring buffer signals an eventfd (`notify_fd`)

The prototype rang the consumer's doorbell **from the BPF program** with
MMIO kfuncs (map a register region, stash a kptr, `bpf_mmio_writel()` on
the hot path). That whole surface is gone. Instead the ring buffer itself
carries the notification: create it with the new `notify_fd` attr naming
an **eventfd**, and every time the ring would wake a consumer (the
existing adaptive policy, including `BPF_RB_FORCE_WAKEUP` /
`BPF_RB_NO_WAKEUP` per commit), the kernel signals that eventfd from the
same irq_work that does the local waitqueue wakeup.

```c
int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

attr.map_type  = BPF_MAP_TYPE_RINGBUF;
attr.map_flags = BPF_F_ARENA_BACKED;
attr.map_extra = arena_fd;
attr.notify_fd = efd;                 /* NEW */
/* ... BPF_MAP_CREATE ... */
```

The BPF program needs **nothing**: plain `bpf_ringbuf_output()` /
`reserve`+`submit`. No kptr dance, no MMIO kfunc set, no per-hook
context concerns — the wakeup policy the ringbuf already implements is
reused as the doorbell policy.

**Who turns the signal into hardware?** The driver that owns the
doorbell register binds the *same eventfd* irqfd-style (the KVM irqfd /
vhost-kick pattern): an `add_wait_queue()` callback that runs inline in
`eventfd_signal()`, consumes the count, and `writel()`s the doorbell
toward the peer node. BPF core knows only eventfd; the driver knows only
eventfd. See the dummy doorbell in `bpf_testmod`
(`BPF_TESTMOD_DB_IOC_BIND`) for a complete reference implementation of
the binding.

Properties that matter for this deployment:

- **One-shot friendly.** The eventfd reference is taken once at
  `BPF_MAP_CREATE` and held by the map. The loader can exit; the wakeup
  keeps firing with no process holding the fd and no fd resolution on
  the datapath. (This is what made the fd-scoped MMIO kfunc awkward —
  it resolved the fd in the caller's process at map time.)
- **Same-host consumers need no driver at all**: poll the eventfd
  directly. `ring_buffer__add_dmabuf(..., notify_fd, ...)` already
  epolls it, and `ring_buffer__poll()` re-arms (reads) the eventfd
  before draining, so the poll loop blocks correctly when idle.
- **Stale `consumer_pos` caveat**: the adaptive wakeup compares against
  the shared consumer page, which a remote consumer only updates via the
  out-of-band sync-back. If that path is lazy, commit with
  `BPF_RB_FORCE_WAKEUP` (signals coalesce at the eventfd) or run a slow
  periodic drain as a safety net.
- `notify_fd` is accepted only on `BPF_MAP_TYPE_RINGBUF`; anything else
  is `-EINVAL`.

The MMIO kfuncs themselves (fd-scoped provider and register-region
variants) are no longer part of this branch; they live on the standalone
`feature/bpf-next/mmio` branch if a use case ever needs raw register
access from BPF.

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

## 7. fd links: dependency edges, one pin per external resource

`BPF_LINK_TYPE_FD` (`attach_type BPF_DEPENDENT_FD`) pins an external fd
in bpffs — and now records **which BPF object depends on it**. The link
takes:

- `target_fd` — the external fd. Only **leaf** file types: eventfd,
  dma-buf, or a driver-registered kind
  (`bpf_fd_link_register_kind(&fops, name)` — register your doorbell /
  DMA-binding fops; a binding must hold `eventfd_ctx` / internal
  attachments, never a `struct file`). Anything else: `-EPERM`.
- `prog_fd` — the **anchor** (mandatory): a BPF link, prog, or map
  (classified by fd type). An fd link always names the object that
  depends on the fd — a link referencing no BPF object is rejected
  (`-EINVAL`). The link holds a reference on the anchor, and
  through the kernel's own graph everything downstream: an attach link
  holds its prog, a prog its `used_maps`, an arena-backed map its arena,
  the arena its dma-buf attachment. On release the anchor is dropped
  *before* the external file.

### The pin structure

One directory per pipeline; each pin names a dependency:

```
/sys/fs/bpf/telemetry0/
├── prog_link    attach link pin      → prog → used_maps (ringbuf, arrays)
├── ring_efd     fd-link { notify eventfd,   anchor: ringbuf map }
├── ring_mbox    fd-link { doorbell binding, anchor: ringbuf map }
└── arena_iova   fd-link { DMA-bind fd,      anchor: arena map   }
```

No separate map pins: each map-anchored fd-link doubles as the map's
pin, and the arena/dma-buf ride the reference graph. The eventfd pin
keeps the eventfd *file* alive, so `POLLHUP` is never delivered to the
doorbell binding and the fd stays reacquirable. Partial operations are
meaningful units — `rm ring_mbox` rewires the doorbell without touching
the ring; `rm arena_iova` fences the device while the CPU-side window
persists — and `rm -r` of the directory is full teardown, unwinding
anchor-before-file at every link.

### Restart: BPF_LINK_GET_DEP_FD

`BPF_OBJ_GET` on a pin returns the *link* fd; the new
`BPF_LINK_GET_DEP_FD { link_fd, which }` unwraps it:
`BPF_FD_LINK_DEP_EXTERNAL` returns the wrapped fd,
`BPF_FD_LINK_DEP_ANCHOR` the anchored link/prog/map fd
(libbpf: `bpf_link_get_dep_fd()`). A restarted loader recovers the full
working set from bpffs paths alone; deeper objects come from
`link_info → prog_id → map_ids → *_GET_FD_BY_ID`. Gated by
`bpf_capable()` plus the pin's FS ACLs. `bpf_link_info.fd` reports
`anchor_kind`/`anchor_id`, and the link's fdinfo prints the anchor, so
the edges are visible from the outside.

### The whole flow

1. **Boot**: carveout heap from DT; drivers register their binding fops
   as pinnable kinds.
2. **Loader (one-shot)**: alloc window dma-buf → dma-buf arena → maps in
   the arena (`notify_fd` = eventfd on the ring) → load + attach prog →
   driver ioctls (DMA bind, doorbell bind on the same eventfd) →
   fd-links per the table above → pin → exit.
3. **Steady state**: zero userspace. Commit → `eventfd_signal()` →
   binding writes the doorbell register → peer wakes, reads the window
   at `arena_off`, syncs `consumer_pos` back out of band.
4. **Restart**: reopen pins, `GET_DEP_FD` both sides of each, resume.
5. **Teardown**: `rm -r` the directory. Reference counts make
   use-after-free unrepresentable; no steady-state partial
   configuration can exist because every partial state requires an
   explicit named unpin.

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
- [ ] Doorbell: create the producer ring with `notify_fd` = an eventfd;
      the doorbell driver binds the same eventfd irqfd-style and writes
      the register. The BPF program just commits records — no MMIO
      kfuncs, no kptr (§5).
- [ ] One bpffs directory per pipeline: attach-link pin + one anchored
      fd-link per external resource (eventfd, doorbell binding, DMA
      bind), each anchored at the map/arena it serves (§7). Register
      driver fd types with `bpf_fd_link_register_kind()`.
- [ ] Restart = reopen pins + `BPF_LINK_GET_DEP_FD`; teardown = remove
      the directory (§7).
